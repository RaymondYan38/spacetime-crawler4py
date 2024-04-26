from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time

from urllib.parse import urlsplit
from collections import defaultdict
from scraper import longest_page, word_to_occurances

class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            time.sleep(self.config.time_delay)
            self.report_questions()

    def report_questions(self):
        num_unique_pages = len(self.frontier.save)
        subdomain_to_occ = defaultdict(int)
        for url, _ in self.frontier.save.values():
            if 'ics.uci.edu' in url:
                split_url = urlsplit(url)
                subdomain_to_occ[split_url.netloc] += 1
            
        with open("q1.txt", "w") as f1:
            f1.write(f"How many unique pages did you find?: {num_unique_pages}\n")
            f1.write("UNIQUE URLS WE SEEN: \n")
            for url, _ in self.frontier.save.values():
                f1.write(f"{url}\n")
        
        with open("q2.txt", "w") as f2:
            f2.write("What is the longest page in terms of the number of words?:\n")
            f2.write(f"Url: {longest_page[0]}\n")
            f2.write(f"Length: {longest_page[1]}\n")
        
        with open("q3.txt", "w") as f3:
            f3.write("What are the 50 most common words in the entire set of pages crawled under these domains?\n")
            x = 0
            for word, occ in sorted(word_to_occurances.items(), key=lambda x: -x[1]):
                f3.write(f"{word}: {occ}\n")
                x += 1
                if x >= 50:
                    break
        
        with open("q4.txt", "w") as f4:
            f4.write("How many subdomains did you find in the ics.uci.edu domain? Submit the list of subdomains ordered alphabetically and the number of unique pages detected in each subdomain.\n")
            for url, occ in sorted(subdomain_to_occ.items(), key=lambda x: x[0]):
                f4.write(f"{url}: {occ}\n")