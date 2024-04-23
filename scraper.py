import os
import re
from urllib.parse import urlparse, urlunparse, urljoin, urlencode, parse_qsl, quote, unquote
from urllib import robotparser
from bs4 import BeautifulSoup
from collections import defaultdict
import logging
import logging_config

NON_HTML_EXTENSIONS_PATTERN = re.compile(
    r"\.(css|js|bmp|gif|jpe?g|ico"
    + r"|png|tiff?|mid|mp2|mp3|mp4"
    + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
    + r"|ps|eps|tex|ppt|pptx|potx|ppsx|sldx|ppam|xlsb|xltx|xltm|xlam|ods|odt|ott|odg|otp|ots|odm|odb"
    + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    + r"|epub|dll|cnf|tgz|sha1"
    + r"|thmx|mso|arff|rtf|jar|csv"
    + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$"
)

# self.save in frontier.py should have the answer to report Q1

longest_page = [None, float("-inf")]

stop_words = ["a",
"about",
"above",
"after",
"again",
"against",
"all",
"am",
"an",
"and",
"any",
"are",
"aren't",
"as",
"at",
"be",
"because",
"been",
"before",
"being",
"below",
"between",
"both",
"but",
"by",
"can't",
"cannot",
"could",
"couldn't",
"did",
"didn't",
"do",
"does",
"doesn't",
"doing",
"don't",
"down",
"during",
"each",
"few",
"for",
"from",
"further",
"had",
"hadn't",
"has",
"hasn't",
"have",
"haven't",
"having",
"he",
"he'd",
"he'll",
"he's",
"her",
"here",
"here's",
"hers",
"herself",
"him",
"himself",
"his",
"how",
"how's",
"i",
"i'd",
"i'll",
"i'm",
"i've",
"if",
"in",
"into",
"is",
"isn't",
"it",
"it's",
"its",
"itself",
"let's",
"me",
"more",
"most",
"mustn't",
"my",
"myself",
"no",
"nor",
"not",
"of",
"off",
"on",
"once",
"only",
"or",
"other",
"ought",
"our",
"ours",
"ourselves",
"out",
"over",
"own",
"same",
"shan't",
"she",
"she'd",
"she'll",
"she's",
"should",
"shouldn't",
"so",
"some",
"such",
"than",
"that",
"that's",
"the",
"their",
"theirs",
"them",
"themselves",
"then",
"there",
"there's",
"these",
"they",
"they'd",
"they'll",
"they're",
"they've",
"this",
"those",
"through",
"to",
"too",
"under",
"until",
"up",
"very",
"was",
"wasn't",
"we",
"we'd",
"we'll",
"we're",
"we've",
"were",
"weren't",
"what",
"what's",
"when",
"when's",
"where",
"where's",
"which",
"while",
"who",
"who's",
"whom",
"why",
"why's",
"with",
"won't",
"would",
"wouldn't",
"you",
"you'd",
"you'll",
"you're",
"you've",
"your",
"yours",
"yourself",
"yourselves"]

word_to_occurances = defaultdict(int)

uniqueURLS = set()
robotstxtdict = {}

def scraper(url, resp):
    can_crawl = politeness(url) 
    if can_crawl:
        links = extract_next_links(url, resp)
        return [link for link in links if is_valid(link)]
    else:
        return []

def politeness(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    can_crawl = True

    # Check if the main domain's robots.txt has already been checked
    if domain in robotstxtdict:
        # Check if the current URL is in the list of subdomains that can't be crawled
        if url in robotstxtdict[domain]['subdomains']:
            can_crawl = False
            return can_crawl
        
        crawl_delay = robotstxtdict[domain]['crawl_delay']
    else:
        rp = robotparser.RobotFileParser()
        rp.set_url(f"{parsed_url.scheme}://{domain}/robots.txt")
        
        try:
            rp.read()
            # Check if the domain has a robots.txt file
            if not rp.can_fetch("*", url):
                can_crawl = False
                return can_crawl
            
            crawl_delay = rp.crawl_delay("*")
            # Cache the crawl delay and subdomains in robotstxtdict
            robotstxtdict[domain] = {
                'crawl_delay': crawl_delay,
                'subdomains': set()
            }
        except Exception as e:
            # Handle exceptions, e.g., network errors, missing robots.txt
            pass

    return can_crawl

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
    base_url = resp.request.url #original url of the pages

    if resp.status == 200 and has_high_content(resp): #checks for valid response and if it has enough textual content
        
        soup = BeautifulSoup(resp.raw_response, 'html.parser')
        for link in soup.find_all('a'):
            tempURL = link.get('href')
            if tempURL:
                clean_url = urljoin(base_url, tempURL) #resolves relative URLs
                clean_url = defragment_url(clean_url) #removes fragmentation

                if clean_url not in extracted_links:
                    extracted_links.append(clean_url)

    if resp.status == 302 or resp.status == 301: #handles redirects
        location_header = resp.headers.get('Location')
        if location_header:
            redirect_url = urljoin(base_url, location_header)
            if is_valid(redirect_url) and has_high_content(redirect_url):
                extracted_links.append(redirect_url)

    return extracted_links

def defragment_url(url):
    # removes the fragment section of url and returns the url without it
    parsed_url = urlparse(url)._replace(fragment='')
    return urlunparse(parsed_url)

"""URLs can represent the same page in multiple ways. For example, http://example.com, 
http://example.com/, http://example.com/index.html, and http://example.com/? could all point to the same resource. Implemened URL 
canonicalization to standardize URLs and avoid crawling the same content multiple times.
"""
def canonicalize_url(url):
    # Parse the URL
    parsed = urlparse(url)
    # Remove fragment identifier
    parsed = parsed._replace(fragment='')
    # Decode encoded characters in the path and query
    decoded_path = unquote(parsed.path)
    decoded_query = unquote(parsed.query)
    # Check if the port matches the default for the scheme
    default_ports = {"http": 80, "https": 443}
    if parsed.port == default_ports.get(parsed.scheme):
        parsed = parsed._replace(netloc=parsed.hostname)
    # Add trailing slash if missing and no file extension present
    if decoded_path and not decoded_path.endswith('/') and not os.path.splitext(decoded_path)[1]:
        decoded_path += '/' 
    # Normalize the path by resolving dot-segments
    normalized_path = os.path.normpath(decoded_path)  
    # Sort and encode query parameters
    query_params = parse_qsl(decoded_query)
    sorted_params = sorted(query_params)
    sorted_query = urlencode(sorted_params)
    # Convert scheme and netloc to lowercase
    parsed = parsed._replace(scheme=parsed.scheme.lower(),
                             netloc=parsed.netloc.lower(),
                             path=quote(normalized_path),  
                             query=sorted_query)
    # Return the canonicalized URL
    return parsed.geturl()

def is_valid(url):
    try:
        # Canonicalize the URL
        canonical_url = canonicalize_url(url)
        # Parse the canonicalized URL
        parsed = urlparse(canonical_url)
        if parsed.scheme not in {"http", "https"}:
            logging.warning(f"URL rejected: {url} - Reason: not HTTP or HTTPS")
            return False
        valid_domains = [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]
        # Check if the domain is one of the specified domains
        if not any(parsed.netloc.endswith(domain) for domain in valid_domains):
            logging.warning(f"URL rejected: {url} - Reason: domain is NOT one of the specified domains")
            return False
        # Extract the path without query parameters
        path_without_query = parsed.path.split('?')[0]
        # Check if the path ends with a non-HTML file extension
        if NON_HTML_EXTENSIONS_PATTERN.match(path_without_query.lower()):
            logging.warning(f"URL rejected: {url} - Reason: path ends with a non-HTML file extension")
            return False
        logging.info(f"URL accepted: {url}")
        return True
    except TypeError:
        print("TypeError for ", parsed)
        raise

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