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
from http.client import HTTPConnection

seen_fingerprints = set()

# Improve performance when the pattern will be used multiple times. 
# When you compile a regex pattern, Python pre-processes it, 
# which can make subsequent matching operations faster.
NON_HTML_EXTENSIONS_PATTERN = re.compile(
    r"\.(apk|css|js|bmp|gif|jpe?g|ico"
    + r"|png|tiff?|mid|mp2|mp3|mp4"
    + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|doc|docx"
    + r"|ps|eps|tex|ppt|pptx|potx|ppsx|sldx|ppam|xlsb|xltx|xltm|xlam|ods|odt|ott|odg|otp|ots|odm|odb"
    + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
    + r"|epub|dll|cnf|tgz|sha1"
    + r"|thmx|mso|arff|rtf|jar|csv|py"
    + r"|rm|smil|wmv|swf|wma|zip|rar|gz|json|mpg|flv|sh|img|sql|war|cgi|xls)$"
)

# problematic prefixes we ran into
prefixes = {"mailto:", "doi:", "javascript:", "skype:", "tel:", "http://timesheet.ics.uci.edu","https://support.ics.uci.edu/passwd/index.php" , "http://dblp.ics.uci.edu/authors", "https://www.ics.uci.edu/ugrad/honors", "https://archive.ics.uci.edu/ml", "http://tippersweb.ics.uci.edu",
                     "https://tippersweb.ics.uci.edu", "http://sli.ics.uci.edu/Ihler-Photos/Main", "http://sli.ics.uci.edu/~ihler/uai-data", "https://ics.uci.edu/~eppstein/pix", "http://metaviz.ics.uci.edu", "https://www.cs.uci.edu/reappointment-of-dean-marios-papaefthymiou",
                       "http://jujube.ics.uci.edu", "http://duke.ics.uci.edu", "http://www.ics.uci.edu/~agelfand/fig", "http://mapgrid.ics.uci.edu/%22", "http://fano", "http://seraja.ics.uci.edu/eva", "https://wics.ics.uci.edu/aspireit-2018/?afg84_page_id=5",
                         "https://fano", "http://alumni.ics.uci.edu/200", "https://password.ics", "http://DataGuard.ics.uci.edu","http://DataProtector.ics.uci.edu","http://hana.ics.uci.edu", "http://sprout.ics.uci.edu", "http://codeexchange.ics.uci.edu",
                         "http://www.ics.uci.edu/pub/", "https://mailman.ics.uci.edu", "http://cocoa-krispies.ics.uci.edu", "https://hombao.ics.uci.edu", "http://cloudberry.ics.uci.edu", "https://www.cs.uci.edu/sandy-irani-and-sameer-singh-receive-distinguished-faculty-awards",
                         "http://asterixdb.ics.uci.edu",  "https://www.ics.uci.edu/community/news/view_news.php"}

longest_page = [None, float("-inf")]
# The k parameter typically determines the number of bits that are retained from the hash value to form the final fingerprint.
simhash_index = SimhashIndex([], k=3)
simhash_dict = dict()
visited_url = set()
DEFAULT_CRAWL_DELAY = 1  # 1 second default crawl delay if not specified in robots.txt

word_to_occurances = defaultdict(int)
last_access_time = {}
robotstxtdict = {}

# /calendar/ matches the literal string "/calendar/"
# \d{4} matches exactly four digit characters, typically representing the year in YYYY format.
# /\d{2}/ matches exactly two digit characters, typically representing the month in MM format.
# /\d{2}/ again matches exactly two digit characters, typically representing the day in DD format.
# \b asserts a word boundary, ensuring that "sessionid" or "sort" is a separate word and not part of a larger word.
# \w+ matches one or more word characters (letters, digits, or underscores).
exclusion_rules = [
    r'/calendar/\d{4}/\d{2}/\d{2}/',
    r'\bsessionid=\w+',
    r'\bsort=\w+',       
]

sitemaps_links = list()

def scraper(url, resp):
    """Main function that checks for politeness, extracts links, and checks if they are valid. Returns a list of all the valid links"""
    global sitemaps_links
    
    can_crawl = politeness(url)  # boolean seeing if we can crawl this given url or not
    if can_crawl:
        links = extract_next_links(url, resp)  # BFSing our way throughout the web through this url
        links.extend(sitemaps_links)  # add links from sitemaps parsing
        sitemaps_links.clear()  # clean out the sitemaps links after adding them to the collection of links
        return [link for link in links if is_valid(link)] # returning valid links
    else:
        return []  # if crawling is not possible or allowed, we return an empty list
    
def politeness_time_delay(domain):
    """Adding a time delay based on crawl delay from robots.txt files for our crawler"""
    global last_access_time
    global robotstxtdict
    
    current_time = time.time()  # get the current time
    last_access = last_access_time[domain]  # get the time this link has been last logged
    time_since_last_access = current_time - last_access  # calculate the time it has been since link has been last logged
    crawl_delay = robotstxtdict[domain]['crawl_delay']  # retrieve the crawl delay time from dict
    if time_since_last_access < crawl_delay: # if not enough time has passed since crawl delay we go into this conditional
        # Wait for the remaining crawl delay time
        time.sleep(crawl_delay - time_since_last_access)
        
def get_urls_from_sitemap(sitemap_url):
    """Getting additional urls directly from the sitemaps and returning them"""
    urls = []  # Initializing an empty list to store URLs
    parsed_url = urljoin(sitemap_url, '/sitemap.xml')  # Constructing the full URL of the sitemap file
    conn = HTTPConnection(parsed_url)  # Establishing an HTTP connection to the sitemap URL
    conn.request('GET', '')  # Sending a GET request to the server to fetch the sitemap content from root url(parsed_url)
    response = conn.getresponse()  # Receiving the response from the server
    if response.status == 200:  # Checking if the response status is 200 (OK) 
        try:
            sitemap_content = response.read()  # Reading the content of the sitemap
            soup = BeautifulSoup(sitemap_content, 'xml')  # Parsing the sitemap content using BeautifulSoup with XML parser
            urls = [loc.text for loc in soup.find_all('loc')]  # Extracting URLs by finding all loc tags and retrieving their text
        except:
            return []
    return urls

def sitemaps_handling(rp):
    """parsing sitemaps.xml files from robots.txt files and appending them to out sitemaps_links list"""
    global sitemaps_links
    
    sitemap_urls = rp.site_maps()  # get site maps
    if sitemap_urls:  # if there are any sitemaps
        for sitemap_url in sitemap_urls:  # iterate through sitemaps urls 
            sitemap_urls_from_helper = get_urls_from_sitemap(sitemap_url)
            for smu in sitemap_urls_from_helper: # parsed links from sitemaps appeded to sitemaps_links
                sitemaps_links.append(smu)

def robots_txt_and_sitemaps_handling(rp, url, domain):
    """Parsing the robots.txt file to check if we are able to crawl at this current moment along with adding information to robotstxtdict"""
    global robotstxtdict
    
    can_crawl = True
    try:
        rp.read()
        
        if not rp.can_fetch("*", url):  # seeing if we are allowed to crawl this specific URL
            can_crawl = False
            return can_crawl
        try:
            sitemaps_handling(rp)  # adding sitemaps links
        except:
            pass
        crawl_delay = rp.crawl_delay("*")  # obtain crawl delay
        
        # Cache the crawl delay and disallowed subdomains in robotstxtdict
        robotstxtdict[domain] = {
            'crawl_delay': crawl_delay if crawl_delay else DEFAULT_CRAWL_DELAY,
        }
        
        # exception handling, URLError was most common
    except HTTPError as e:
        # Log other HTTP errors 
        logging.error(f"HTTPError accessing robots.txt for domain {domain}: {e}")
        can_crawl = False
    except URLError as e:
        # Log URL errors 
        logging.error(f"URLError accessing robots.txt for domain {domain}: {e}")
        can_crawl = False
    except Timeout as e:
        # Log timeout errors 
        logging.error(f"Timeout accessing robots.txt for domain {domain}: {e}")
        can_crawl = False
    except Exception as e:
        # Handle other exceptions
        logging.error(f"Error accessing robots.txt for domain {domain}: {e}")
        can_crawl = False
    return can_crawl

def politeness(url):
    """Making sure that we are allowed to crawl the url we are looking at when given to us from the frontier based on politeness"""
    global last_access_time
    global robotstxtdict
    # The urlparse function from the urllib.parse module in Python is used to parse a URL string into its components, 
    # such as scheme, network location, path, parameters, query, and fragment. It breaks down a URL string into several parts, 
    # making it easier to work with each component individually.
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    can_crawl = True
    # Check if the main domain's robots.txt has already been checked
    if domain in robotstxtdict:
        politeness_time_delay(domain)
        return can_crawl    
    else:
        rp_url = f"{parsed_url.scheme}://{domain}/robots.txt"  # url to robots.txt for domains
        rp = robotparser.RobotFileParser()  
        rp.set_url(rp_url)
        can_crawl = robots_txt_and_sitemaps_handling(rp, url, domain)  # checking if a site can be crawled or not
        
    last_access_time[domain] = time.time()  # updating last accesses time of a link
    return can_crawl

def tokenize_content(content):
    """"Uses word_tokenize from nltk library to split content into tokens. Returns the Beautiful soup object, text content of the file, and tokens"""
    soup = BeautifulSoup(content, "lxml") # using bs4 to take information from website, lxml more efficient and fixes recursion errors based on AI tutor
    text_content = soup.get_text()
    tokens = word_tokenize(text_content.lower()) # tokenizing
    return soup, text_content, tokens

def extract_next_links(url, resp):
    """extracting additional links from url from the frontier that can potentially be added to the frontier along with near duplicate checking"""
    global longest_page
    global simhash_index
    global seen_fingerprints
    global word_to_occurances
    
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
            soup, text_content, tokens = tokenize_content(content)
        except:
            return []
        
        if has_high_content(soup, text_content, content):
        # Generate a hash of the content for exact duplicate detection
            content_hash = hashlib.sha256(content).hexdigest()
            
            features = Counter(tokens) #getting the simhash for this page
            simhash = Simhash(features)
            
            is_near_duplicate_result = is_near_duplicate(url, simhash, simhash_index)

            # Check if we have already seen this content or if it is near duplicate
            if content_hash not in seen_fingerprints and not is_near_duplicate_result:
                #tokenize and track word occurences for report
                tokens_without_stop_words = [token for token in tokens if token not in sw and len(token) >= 2]
                valid_tokens_len = len(tokens)
                if valid_tokens_len > longest_page[1]:  # updating longest page found
                    longest_page[0] = url
                    longest_page[1] = valid_tokens_len
                
                for token in tokens_without_stop_words:  # updating most common words found dictionary
                    if token.isalpha():
                        word_to_occurances[token] += 1

                seen_fingerprints.add(content_hash)  # Add new fingerprint to the set

                for link in soup.find_all('a'): #iterates through the links in the webpage
                    tempURL = link.get('href')
                    if tempURL:
                        clean_url = urljoin(base_url, tempURL) #resolves relative URLs
                        clean_url = defragment_url(clean_url) #removes fragmentation
                        extracted_links.add(clean_url)     
    elif resp is None or resp.raw_response is None: #if no content or response we return empty list
        return []
    elif resp and resp.status in {301, 302, 307, 308}: #handles redirects by getting location header and joining it with the base_url
        location_header = resp.headers.get('Location')
        if location_header:
            redirect_url = urljoin(base_url, location_header)
            extracted_links.add(redirect_url)
    elif resp.status not in {200, 301, 30, 307, 308}: # if not in a given set of status codes, we return empty list
        return []
    extracted_links = list(extracted_links)
    return extracted_links

def canonicalize_url(url):
    """"canonicalizing URLs to standardize them for easier work"""
    # Parse the URL
    try:
        url = defragment_url(url)
        parsed = urlparse(url)
        if not parsed:  # Check if parsed is None
            return None
        
        # From AI helper when asked for suggestions for canonicalization: You decode percent-encoded characters in the path and query, which can help in recognizing identical paths and queries that are represented differently.
        # When you decode the URL's path and query components using unquote, any percent-encoded characters are converted back to their original form.
        # For example, if you have a URL like this: https://example.com/path%20with%20spaces/page?query_param=value%20with%20spaces
        # After decoding, it would look like this: https://example.com/path with spaces/page?query_param=value with spaces
        decoded_path = unquote(parsed.path) # Decode encoded characters in the path and query
        decoded_query = unquote(parsed.query)
        
        # If the port number specified in the URL matches the default port for its scheme, 
        # it means the port number is redundant (since it's the default one). In such a case, 
        # there's no need to explicitly include it in the URL. Therefore, parsed = parsed._replace(netloc=parsed.hostname) 
        # is used to replace the entire netloc component of the parsed URL with just the hostname component. 
        # This effectively removes the port number from the URL.
        # This section ensures that URLs are canonicalized by removing the port number if it matches the default port number for the scheme. 
        # This helps in standardizing URLs and making them more concise.
        default_ports = {"http": 80, "https": 443}  # Check if the port matches the default for the scheme
        if parsed.port == default_ports.get(parsed.scheme):
            parsed = parsed._replace(netloc=parsed.hostname)  # note netloc is the same as authority, https://www.example.com:8080/path/to/resource, netloc: www.example.com:8080
        
        # Add a trailing slash when there is no file extension, which can help in treating directory URLs uniformly
        if decoded_path and not decoded_path.endswith('/') and not os.path.splitext(decoded_path)[1]: # Add trailing slash if missing and no file extension present
            decoded_path += '/' 
        
        normalized_path = os.path.normpath(decoded_path)  # The path component of the URL is normalized by resolving any dot-segments (e.g., /./ and /../)
        
        # query_params will be a list of tuples, where each tuple represents a key-value pair extracted from the URL's query string.
        # ex. query_params = [('param1', 'value1'), ('param2', 'value2') ]
        query_params = parse_qsl(decoded_query)  # Sort and encode query parameters
        
        # Define known session ID and tracking parameter names
        session_id_params = ["sessionid", "sid", "phpsessid"]
        tracking_params = ["utm_source", "utm_medium", "utm_campaign"]
        
        # cleaned up params and sorting them to make some that maybe unordered the same and removing session id and tracking params
        # Session ID parameters (sessionid, sid, phpsessid, etc.) often result in unique URLs for each session, even if the actual 
        # content is the same. Removing these parameters ensures that the same content is consistently represented by the same URL, 
        # which improves caching efficiency.
        query_params = [(key, value) for key, value in query_params if key.lower() not in session_id_params]  # Remove session ID parameters
        query_params = [(key, value) for key, value in query_params if key.lower() not in tracking_params]  # Remove tracking parameters
        sorted_params = sorted(query_params)
        sorted_query = urlencode(sorted_params) # now back to something like this: 'category=news&page=1&sort=asc'
        
        # Convert scheme and netloc to lowercase
        parsed = parsed._replace(scheme=parsed.scheme.lower(),
                                netloc=parsed.netloc.lower(),
                                path=quote(normalized_path),  
                                query=sorted_query)
        # Return the canonicalized URL
        return parsed.geturl() if parsed else None
    except Exception as e:  # if for some reason some error occurs during canonicalizing, return None
        return None

def invalid_prefix_check(url):
    """filtering out prefixes of troublesome sites that cause issues"""
    global prefixes
    
    # check with any urls prefixes or urls match notable BAD urls to skip that cause issues
    if any(url.startswith(prefix) for prefix in prefixes):
        logging.warning(f"URL rejected: {url} - Reason: mailto, JavaScript, or Skype URL")
        return False
    return True

def bad_url_filter(parsed, url):
    """Filtering out bad urls based on pathing, schemes, domains, and extensions"""
    # check if any of these strings are in the path which leads to undesdired results
    if '.pdf' in parsed.path or '/pdf/' in parsed.path or 'json' in parsed.path or 'doku.php' in parsed.path:
        return False
    
    # only want HTTP or HTTPS
    if parsed.scheme not in {"http", "https"}:
        logging.warning(f"URL rejected: {url} - Reason: not HTTP or HTTPS")
        return False
    
    # only want the valid domains
    valid_domains = [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]
    # Check if the domain is one of the specified domains
    if not any(parsed.netloc.endswith(domain) for domain in valid_domains):
        logging.warning(f"URL rejected: {url} - Reason: domain is NOT one of the specified domains")
        return False
    
    # takeaway most non HTML extensions
    if NON_HTML_EXTENSIONS_PATTERN.search(parsed.geturl().lower()):
        logging.warning(f"URL rejected: {url} - Reason: URL ends with a non-HTML file extension")
        return False
    return True

def cycle_detection(parsed, url):
    """multiple checks to see if we are in a cycle, returning a boolean indicating whether or not we are"""
    global visited_url
    global exclusion_rules
    
    # Check if the path length exceeds the threshold because noticed super long paths almost always indicate a cycle
    max_path_length = 10
    path_splt = parsed.path.split('/')
    len_path_splt = len(path_splt)
    if len_path_splt > max_path_length:
        logging.warning(f"URL rejected: {url} - Reason: path length exceeds threshold")
        return False
    
    # seeing if there are duplicates in the path which all most always mean we are in a cycle
    if len_path_splt != len(set(path_splt)):
        logging.warning(f"URL rejected: {url} - Reason: Duplicates in path indicating we might be in a cycle")
        return False
    
    # taking away obvious traps/infinite loops such as calenders, etc.
    for rule in exclusion_rules:
        if re.search(rule, parsed.geturl()):
            logging.warning(f"URL rejected: {url} - Reason: matches exclusion rule ({rule})")
            return False
    
    # making sure we do not run into the same URL multiple times
    if parsed.geturl() in visited_url:
        return False
    else:
        visited_url.add(parsed.geturl())
        return True

def is_valid(url):
    """"Checks if url is valid by our definition and canonicalizes it. Returns a boolean value"""
    url_is_valid = True
    try:
        url_is_valid = invalid_prefix_check(url)
        
        if not url_is_valid:
            return False
        
        canonical_url = canonicalize_url(url) # Canonicalize the URL to avoid dupes with different URLs
        if canonical_url is None:
            logging.warning(f"URL could not be accessed because canonical_url is None: {url}")
            return False
        # Parse the canonicalized URL
        parsed = urlparse(canonical_url)
        url_is_valid = bad_url_filter(parsed, url) and cycle_detection(parsed, url)
        return url_is_valid
    except Exception as e:
        return False

def defragment_url(url):
    """removes the fragment section of url and returns the url without it"""

    parsed_url = urlparse(url)._replace(fragment='')
    return urlunparse(parsed_url)

def has_high_content(soup, text, html_content):
    """checks if response has enough textual content by comparing the word to html tag ratio to a given threshold"""
    max_file_size = 2 * 1024 * 1024
    if len(html_content) > max_file_size:  # want to avoid large files
        return False
    else :
        text_length = len(text)
        total_length = len(str(soup))
        
        if total_length == 0:  # return false for empty page
            return False
        
        text_to_html_ratio = text_length / total_length  # metric based on html to text_length ratio
        word_count = len(text.split())

        headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])  # another metric to determine high textual content using hea
        paragraphs = soup.find_all('p')

        return word_count >= 100 or text_to_html_ratio >= 0.25 or len(headers) >= 3 or len(paragraphs) >= 5  # determine high content based on multiple metrics

def is_near_duplicate(url, simhash, simhash_index):
    """Uses simhashing to detect near duplicates of webpages"""
    global simhash_dict
    
    similarity_threshold = 0.9
    #checks if webpage is near duplicate by using simhashing
    near_duplicates = simhash_index.get_near_dups(simhash)
    is_duplicate = any(simhash_dict[dup].distance(simhash) <= similarity_threshold for dup in near_duplicates)
    if is_duplicate:
        return True
    else:
        # if not a duplate, we add simhash index of url to its identifier
        simhash_dict[url] = simhash
        simhash_index.add(url, simhash)
        return False
