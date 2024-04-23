import os
import re
from urllib.parse import urlparse, urlencode, parse_qsl, quote, unquote
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
    return list()

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
