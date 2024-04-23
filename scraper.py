import re
from urllib.parse import urlparse
from urllib import robotparser

robotstxtdict = {}

def scraper(url, resp):
    politeness(url)
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

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
    return list()

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
