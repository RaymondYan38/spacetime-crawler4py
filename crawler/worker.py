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

            self.generate_answers()

    def generate_answers(self):
        q1_file = open("Question 1a.txt", "w")
        q2_file = open("Question 2a.txt", "w")
        q3_file = open("Question 3a.txt", "w")
        q4_file = open("Question 4a.txt", "w")

        subdomains = defaultdict(int)
        q1_file.write(f"\n\nNumber of Unique URLs: {len(self.frontier.save)}\n\n")
        for url, _ in self.frontier.save.values():
            if 'ics.uci.edu' in url:
                parsed_url = urlsplit(url)
                subdomains[parsed_url.netloc] += 1
            q1_file.write(url + "\n")

        q1_file.write("\n\nALL URLS:\n\n")
        q2_file.write(f"\n\nLongest page and number of words: {longest_page[0]} , {longest_page[1]}\n\n")
        q3_file.write("\n\n50 most common words in the entire set of pages crawled under these domains:\n")
        for word, freq in sorted(word_to_occurances.items(), key=lambda x: -x[1]):
            q3_file.write(f"{word} -> {freq}\n")
        
        q4_file.write("Subdomains in ics.uci.edu and number of unique pages: ")
        for url, freq in sorted(subdomains.items(), key=lambda x: x[0]):
            q4_file.write(f"{url} -> {freq}\n")

        q1_file.close()
        q2_file.close()
        q3_file.close()
        q4_file.close()