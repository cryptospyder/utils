import BeautifulSoup
import Paste
import urllib2
import time
import Queue
import threading
import sys
import datetime
import random
import os
import re
 
pastesseen = set()
pastes = Queue.Queue()
 
def downloader():
    while True:
        content_t = Paste.Paste()
        paste = pastes.get()
        fn = "pastebins/%s-%s.txt" % (paste, datetime.datetime.today().strftime("%Y-%m-%d"))
        content = urllib2.urlopen("http://pastebin.com/raw.php?i=" + paste).read()
        content_t.text = content
        delay = 1.1 # random.uniform(1, 3)

        if "requesting a little bit too much" in content:
            print "Throttling... requeuing %s" % paste
            pastes.put(paste)
            time.sleep(0.1)
        elif content_t.match():
            f = open(fn, "wt")
            f.write(content)
            f.close()
            sys.stdout.write("Downloaded %s, waiting %f sec\n" % (paste, delay))
        else:
            sys.stdout.write("No Match Found in %s, waiting %f sec\n" % (paste, delay))
        
        
        time.sleep(delay)
        pastes.task_done()
 
def scraper():
    scrapecount = 0
    while scrapecount < 10:
        html = urllib2.urlopen("http://www.pastebin.com").read()
        soup = BeautifulSoup.BeautifulSoup(html)
        ul = soup.find("ul", "right_menu")
        for li in ul.findAll("li"):
            href = li.a["href"]
            if href in pastesseen:
                sys.stdout.write("%s already seen\n" % href)
            else:
                href = href[1:] # chop off leading /
                pastes.put(href)
                pastesseen.add(href)
                sys.stdout.write("%s queued for parsing\n" % href)
        delay = 12 # random.uniform(6,10)
        time.sleep(delay)
        scrapecount += 1
 
while True:
    num_workers = 1
    for i in range(num_workers):
        t = threading.Thread(target=downloader)
        t.setDaemon(True)
        t.start()
     
    if not os.path.exists("pastebins"):
        os.mkdir("pastebins") # Thanks, threecheese!
     
    s = threading.Thread(target=scraper)
    s.start()
    s.join()