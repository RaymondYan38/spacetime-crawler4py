import os
import re
import time
from urllib.error import HTTPError, URLError
from socket import timeout as Timeout
from urllib.parse import urlparse, urlunparse, urljoin, urlencode, parse_qsl, quote, unquote
from urllib import robotparser
from bs4 import BeautifulSoup
from collections import defaultdict
import logging
import logging.config
import hashlib
import nltk
nltk.download('punkt')
from nltk.tokenize import word_tokenize
nltk.download('stopwords')
from nltk.corpus import stopwords
sw = stopwords.words('english')
from collections import Counter
from simhash import Simhash, SimhashIndex

seen_fingerprints = set()
robotstxtdict = {}
NON_HTML_EXTENSIONS_PATTERN = re.compile(
    r"\.(apk|css|js|bmp|gif|jpe?g|ico"
    + r"|png|tiff?|mid|mp2|mp3|mp4"
    + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
    + r"|ps|eps|tex|ppt|pptx|potx|ppsx|sldx|ppam|xlsb|xltx|xltm|xlam|ods|odt|ott|odg|otp|ots|odm|odb"
    + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    + r"|epub|dll|cnf|tgz|sha1"
    + r"|thmx|mso|arff|rtf|jar|csv"
    + r"|rm|smil|wmv|swf|wma|zip|rar|gz|json|mpg|flv|sh|img|sql)$"
)

# self.save in frontier.py should have the answer to report Q1

longest_page = [None, float("-inf")]
simhash_index = SimhashIndex([], k=3)
simhash_dict = dict()
visited_url = set()
DEFAULT_CRAWL_DELAY = 1

word_to_occurances = defaultdict(int)
last_access_time = {}
robotstxtdict = {}

exclusion_rules = [
    r'/calendar/\d{4}/\d{2}/\d{2}/',
    r'\bsessionid=\w+',
    r'\bsort=\w+',       
    # Add more exclusion rules if needed
]

def detect_repetitive_pattern(url):
    # Function to detect repetitive patterns in URLs
    # For example, if a URL contains repetitive segments like /stayconnected/stayconnected/..., it's likely a trap
    segments = urlparse(url).path.split('/')
    # Check if any segment is repeated multiple times
    for i in range(2, len(segments)):
        if all(j < len(segments) and segments[j] == segments[j - 1] for j in range(i, i * 2)):
            return True
    return False

def scraper(url, resp):
    can_crawl = politeness(url) 
    if can_crawl:
        links = extract_next_links(url, resp)
        # Filter out URLs with repetitive patterns
        links = [link for link in links if not detect_repetitive_pattern(link)]
        return [link for link in links if is_valid(link)]
    else:
        print(f"politeness is false for this url: {url}")
        return []
    

def politeness(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    can_crawl = True
    # Check if the main domain's robots.txt has already been checked
    if domain in robotstxtdict:
        # Check if the current URL is in the disallowed subdomains that can't be crawled
        # if url in robotstxtdict[domain]['disallowed']:
        #     can_crawl = False
        #     return can_crawl 
        current_time = time.time()
        last_access = last_access_time[domain]
        time_since_last_access = current_time - last_access
        crawl_delay = robotstxtdict[domain]['crawl_delay']
        if time_since_last_access < crawl_delay:
            # Wait for the remaining crawl delay time
            time.sleep(crawl_delay - time_since_last_access)
        return can_crawl    
    else:
        rp_url = f"{parsed_url.scheme}://{domain}/robots.txt"
        rp = robotparser.RobotFileParser()
        rp.set_url(rp_url)
        try:
            rp.read()
            # Check if the domain has a robots.txt file
            if not rp.can_fetch("*", url):
                can_crawl = False
                return can_crawl
            crawl_delay = rp.crawl_delay("*")
            # Cache the crawl delay and disallowed subdomains in robotstxtdict
            robotstxtdict[domain] = {
                'crawl_delay': crawl_delay if crawl_delay else DEFAULT_CRAWL_DELAY,
            }
            # robotstxtdict[domain] = {
            #     'crawl_delay': crawl_delay if crawl_delay else DEFAULT_CRAWL_DELAY,
            #     'disallowed': set(rp.disallowed("*")),  # Store all disallowed subdomains
            #     'allowed': set(rp.allowed("*"))  # Store all allowed subdomains
            # }
            # Check if the URL matches any disallowed patterns
            # for pattern in robotstxtdict[domain]['disallowed']:
            #     # Convert wildcard pattern to regex and match against the URL
            #     if '*' in pattern:
            #         regex_pattern = re.escape(pattern).replace(r'\*', '.*')
            #         if re.match(regex_pattern, url):
            #             can_crawl = False
            #             break
            #     elif url.startswith(pattern):
            #         # Check if the URL starts with the disallowed pattern
            #         can_crawl = False
            #         break
        except HTTPError as e:
            if e.code == 404:
                # File not found, allow crawling by default
                can_crawl = True
            else:
                # Log other HTTP errors and set a flag to retry or skip
                logging.error(f"HTTPError accessing robots.txt for domain {domain}: {e}")
                can_crawl = False
        except URLError as e:
            # Log URL errors and possibly retry after a delay
            logging.error(f"URLError accessing robots.txt for domain {domain}: {e}")
            can_crawl = False
        except Timeout as e:
            # Log timeout errors and implement a retry strategy
            logging.error(f"Timeout accessing robots.txt for domain {domain}: {e}")
            can_crawl = False
        except Exception as e:
            # Handle other exceptions
            logging.error(f"Error accessing robots.txt for domain {domain}: {e}")
            can_crawl = False
    last_access_time[domain] = time.time()
    return can_crawl

def extract_next_links(url, resp):
    global longest_page
    global simhash_index
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    extracted_links = set()
    base_url = resp.url #original url of the pages
    if resp.status == 200 and resp.raw_response and resp.raw_response.content: #checks for valid response 
        content = resp.raw_response.content
        try:
            soup = BeautifulSoup(content, "lxml")
            text_content = soup.get_text()
            tokens = word_tokenize(text_content.lower())
        except:
            return []
        if has_high_content(soup, text_content, content):
        # Generate a hash of the content for exact duplicate detection
            content_hash = hashlib.sha256(content).hexdigest()
            
            features = Counter(tokens) #getting the simhash for this page
            simhash = Simhash(features)
            
            is_near_duplicate_result = is_near_duplicate(url, simhash, simhash_index)
            
            if is_near_duplicate_result:
                print(f"SIMHASH THING DETECED A NEAR DUPLICATE FOR THIS URL: {url}")

            # Check if we have already seen this content or if it is near duplicate
            if content_hash not in seen_fingerprints and not is_near_duplicate_result:
                #tokenize and track word occurences for report
                tokens_without_stop_words = [token for token in tokens if token not in sw and len(token) >= 2]
                valid_tokens_len = len(tokens)
                
                if valid_tokens_len > longest_page[1]:
                    longest_page = [url, valid_tokens_len]
                
                for token in tokens_without_stop_words:
                    word_to_occurances[token] += 1

                # simhash_index.add(content_hash, simhash) #add simhash to the index
                seen_fingerprints.add(content_hash)  # Add new fingerprint to the set

                for link in soup.find_all('a'): #iterates through the links in the webpage
                    tempURL = link.get('href')
                    if tempURL:
                        clean_url = urljoin(base_url, tempURL) #resolves relative URLs
                        clean_url = defragment_url(clean_url) #removes fragmentation
                        extracted_links.add(clean_url)     
        else:
            print(f"This url DO NOT HAVE HIGH CONTENT SO WE IGNORE: {url}")
    elif resp is None or resp.raw_response is None:
        return []
    elif resp.status not in {200, 301, 302}:
        print(resp.error)
        return[]
    elif not (url == resp.raw_response.url):
        return [resp.raw_response.url]
    elif resp and resp.status in {301, 302}: #handles redirects
        location_header = resp.headers.get('Location')
        if location_header:
            redirect_url = urljoin(base_url, location_header)
            extracted_links.add(redirect_url)
    extracted_links = list(extracted_links)
    print(f"EXTRACTED LINKS FROM THIS URL: {url} ARE: {extracted_links}")
    return extracted_links

"""URLs can represent the same page in multiple ways. For example, http://example.com, 
http://example.com/, http://example.com/index.html, and http://example.com/? could all point to the same resource. Implemened URL 
canonicalization to standardize URLs and avoid crawling the same content multiple times.
"""
def canonicalize_url(url):
    # Parse the URL
    try:
        parsed = urlparse(url)
        if not parsed:  # Check if parsed is None
            return None
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
        # Define known session ID and tracking parameter names
        session_id_params = ["sessionid", "sid", "phpsessid"]  # Add more if needed
        tracking_params = ["utm_source", "utm_medium", "utm_campaign"]  # Add more if needed
        # Remove session ID parameters
        query_params = [(key, value) for key, value in query_params if key.lower() not in session_id_params]
        # Remove tracking parameters
        query_params = [(key, value) for key, value in query_params if key.lower() not in tracking_params]
        sorted_params = sorted(query_params)
        sorted_query = urlencode(sorted_params)
        # Convert scheme and netloc to lowercase
        parsed = parsed._replace(scheme=parsed.scheme.lower(),
                                netloc=parsed.netloc.lower(),
                                path=quote(normalized_path),  
                                query=sorted_query)
        # Return the canonicalized URL
        return parsed.geturl() if parsed else None
    except Exception as e:
        print(f"Error canonicalizing URL: {url} with this exception: {e}")
        return None

def is_valid(url):
    try:
        if url.startswith("mailto:") or url.startswith("doi:") or url.startswith("javascript:") or url.startswith("skype:") or url.startswith("tel:") or url.startswith("https://www.ics.uci.edu/ugrad/honors") or url.startswith("https://archive.ics.uci.edu/ml") or url.startswith("http://tippersweb.ics.uci.edu") or url.startswith("http://sli.ics.uci.edu/Ihler-Photos/Main") or url.startswith("http://sli.ics.uci.edu/~ihler/uai-data"):
            logging.warning(f"URL rejected: {url} - Reason: mailto, JavaScript, or Skype URL")
            return False
        # Canonicalize the URL
        canonical_url = canonicalize_url(url)
        if canonical_url is None:
            logging.warning(f"URL could not be accessed because canonical_url is None: {url}")
            return False
        # Parse the canonicalized URL
        parsed = urlparse(canonical_url)
        if '.pdf' in parsed.path or '/pdf/' in parsed.path or 'json' in parsed.path or 'doku.php' in parsed.path:
            return False
        
        if parsed.scheme not in {"http", "https"}:
            logging.warning(f"URL rejected: {url} - Reason: not HTTP or HTTPS")
            return False
        valid_domains = [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]
        # Check if the domain is one of the specified domains
        if not any(parsed.netloc.endswith(domain) for domain in valid_domains):
            logging.warning(f"URL rejected: {url} - Reason: domain is NOT one of the specified domains")
            return False
        if NON_HTML_EXTENSIONS_PATTERN.search(parsed.geturl().lower()):
            logging.warning(f"URL rejected: {url} - Reason: URL ends with a non-HTML file extension")
            return False
        
        # domain = parsed.hostname
        # if domain in robotstxtdict:
        #     for pattern in robotstxtdict[domain]['disallowed']:
        #         if '*' in pattern:
        #             # Convert wildcard pattern to regex
        #             pattern_regex = pattern.replace('*', '.*')
        #             # Add anchors (^ and $) to match from the beginning and end of the path
        #             pattern_regex = '^' + pattern_regex + '$'
        #             if re.match(pattern_regex, parsed.path):
        #                 logging.warning(f"URL rejected: {url} - Reason: matches disallowed pattern in robots.txt")
        #                 return False
        #         else:
        #             # No wildcard, so simply match the pattern
        #             if parsed.path.startswith(pattern):
        #                 logging.warning(f"URL rejected: {url} - Reason: matches disallowed pattern in robots.txt")
        #                 return False
        # Check if the path length exceeds the threshold
        max_path_length = 10
        path_splt = parsed.path.split('/')
        len_path_splt = len(path_splt)
        if len_path_splt > max_path_length:
            logging.warning(f"URL rejected: {url} - Reason: path length exceeds threshold")
            return False
        
        if len_path_splt != len(set(path_splt)):
            logging.warning(f"URL rejected: {url} - Reason: Duplicates in path indicating we might be in a cycle")
            return False
        
        for rule in exclusion_rules:
            if re.search(rule, parsed.geturl()):
                logging.warning(f"URL rejected: {url} - Reason: matches exclusion rule ({rule})")
                return False

        if parsed.geturl() in visited_url:
            print(f"REPEATED URL IS FOUND IN VISITED SET, IGNORING: {url}")
            return False
        
        else:
            visited_url.add(parsed.geturl())
        print("------------------------------------------------------------------------")
        print(f"URL validated/accepted: {url}")
        print("------------------------------------------------------------------------")
        return True
    except Exception as e:
        print("Exception in is_valid: ", e)

def defragment_url(url):
    # removes the fragment section of url and returns the url without it
    parsed_url = urlparse(url)._replace(fragment='')
    return urlunparse(parsed_url)

def has_high_content(soup, text, html_content):
    """checks if response has enough textual content by comparing the word to html tag ratio to a given threshold"""
    max_file_size = 2 * 1024 * 1024
    if len(html_content) > max_file_size: #want to avoid large files
        return False
    else :
        text_length = len(text)
        total_length = len(str(soup))
        
        if total_length == 0:
            return False
        
        text_to_html_ratio = text_length / total_length
        word_count = len(text.split())

        headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        paragraphs = soup.find_all('p')

        return word_count >= 100 or text_to_html_ratio >= 0.25 or len(headers) >= 3 or len(paragraphs) >= 5

def is_near_duplicate(url, simhash, simhash_index):
    similarity_threshold = 0.9
    #checks if webpage is near duplicate by using simhashing
    near_duplicates = simhash_index.get_near_dups(simhash)
    is_duplicate = any(simhash_dict[dup].distance(simhash) <= similarity_threshold for dup in near_duplicates)
    if is_duplicate:
        return True
    else:
        simhash_dict[url] = simhash
        simhash_index.add(url, simhash)
        return False
    # for near_duplicate in near_duplicates:
        
    #     if simhash.distance(Simhash(near_duplicate)) <= similarity_threshold:
    #         return True
    # return False