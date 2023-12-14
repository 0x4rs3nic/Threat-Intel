## Copyright 0x4rs3nic

import requests
import logging
import json
from datetime import datetime
import feedparser
import time
import dateutil.parser

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Create a logger object
logger = logging.getLogger(__name__)


def cut_string(string, length):
  return (string[:(length - 3)].strip() +
          "...") if len(string) > length else string


def format_datetime(article_datetime):
  if not isinstance(article_datetime, datetime):
    try:
      article_datetime = dateutil.parser.isoparse(article_datetime)
    except ValueError:
      return article_datetime.split("T")

  return [
      article_datetime.strftime("%d, %b %Y"),
      article_datetime.strftime("%H:%M")
  ]


def get_news_from_rss(rss_item):
  logger.debug(f"Querying RSS feed at {rss_item[0]}")
  feed_entries = feedparser.parse(rss_item[0]).entries

  # This is needed to ensure that the oldest articles are proccessed first. See https://github.com/vxunderground/ThreatIntelligenceDiscordBot/issues/9 for reference
  for rss_object in feed_entries:
    rss_object["source"] = rss_item[1]
    try:
      rss_object["publish_date"] = time.strftime("%Y-%m-%dT%H:%M:%S",
                                                 rss_object.published_parsed)
    except:
      rss_object["publish_date"] = time.strftime("%Y-%m-%dT%H:%M:%S",
                                                 rss_object.updated_parsed)

  return feed_entries


private_rss_feed_list = [
    ['https://grahamcluley.com/feed/', 'Graham Cluley'],
    ['https://threatpost.com/feed/', 'Threatpost'],
    ['https://krebsonsecurity.com/feed/', 'Krebs on Security'],
    ['https://www.darkreading.com/rss.xml', 'Dark Reading'],
    ['http://feeds.feedburner.com/eset/blog', 'We Live Security'],
    [
        'https://davinciforensics.co.za/cybersecurity/feed/',
        'DaVinci Forensics'
    ], ['https://blogs.cisco.com/security/feed', 'Cisco'],
    [
        'https://www.infosecurity-magazine.com/rss/news/',
        'Information Security Magazine'
    ], ['http://feeds.feedburner.com/GoogleOnlineSecurityBlog', 'Google'],
    ['http://feeds.trendmicro.com/TrendMicroResearch', 'Trend Micro'],
    ['https://www.bleepingcomputer.com/feed/', 'Bleeping Computer'],
    ['https://www.proofpoint.com/us/rss.xml', 'Proof Point'],
    ['http://feeds.feedburner.com/TheHackersNews?format=xml', 'Hacker News'],
    ['https://www.schneier.com/feed/atom/', 'Schneier on Security'],
    ['https://www.binarydefense.com/feed/', 'Binary Defense'],
    ['https://securelist.com/feed/', 'Securelist'],
    ['https://research.checkpoint.com/feed/', 'Checkpoint Research'],
    ['https://www.virusbulletin.com/rss', 'VirusBulletin'],
    ['https://modexp.wordpress.com/feed/', 'Modexp'],
    ['https://www.tiraniddo.dev/feeds/posts/default', 'James Forshaw'],
    ['https://blog.xpnsec.com/rss.xml', 'Adam Chester'],
    ['https://msrc-blog.microsoft.com/feed/', 'Microsoft Security'],
    ['https://www.recordedfuture.com/feed', 'Recorded Future'],
    ['https://www.sentinelone.com/feed/', 'SentinelOne'],
    ['https://redcanary.com/feed/', 'RedCanary'],
    ['https://cybersecurity.att.com/site/blog-all-rss', 'ATT']
]

gov_rss_feed_list = [
    ["https://www.cisa.gov/uscert/ncas/alerts.xml", "US-CERT CISA"],
    ["https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "NCSC"],
    [
        "https://www.cisecurity.org/feed/advisories",
        "Center of Internet Security"
    ],
]


def append_to_json(data, filename):
  try:
    # Try to read the existing content from the file
    with open(filename, 'r') as file:
      existing_data = json.load(file)
  except FileNotFoundError:
    # If the file doesn't exist, initialize with an empty list
    existing_data = []

  # Check for duplicates based on some criteria (e.g., assuming a unique key)
  unique_keys = set(item.get('unique_key') for item in existing_data)
  new_data = [
      item for item in data if item.get('unique_key') not in unique_keys
  ]

  # Extend the existing data with the new data (excluding duplicates)
  existing_data.extend(new_data)

  # Write the extended data back to the file
  with open(filename, 'w') as file:
    json.dump(existing_data, file, indent=2)


def get_ransomware_news(source):
  logger.info("Querying latest ransomware information")
  posts = requests.get(source).json()

  for post in posts:
    post["publish_date"] = post["discovered"]
    post["title"] = "Post: " + post["post_title"]
    post["source"] = post["group_name"]

  return posts


def format_single_article(article):
  description = ""

  if "summary" in article:
    for text_part in article["summary"].split("."):
      if not (len(description) + len(text_part)) > 250:
        description += text_part + "."
      else:
        description += ".."
        break
  source_text = f"Source: {article['source']}"
  date_text = "Date: " + str(format_datetime(article["publish_date"]))

  message = {
      "title": article["title"],
      "url": article["link"],
      "description": description,
      "source": source_text,
      "date": date_text,
  }

  return message


ransomeware_source = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

raw_data_ransomware = get_ransomware_news(ransomeware_source)

logger.info("Recieved ransomware data")


def log_current_time(post_type):
  current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  new_log_entry = f"{post_type}: {current_time}\n"

  log_file_path = "log.txt"

  # Read existing content
  with open(log_file_path, "r") as log_file:
    lines = log_file.readlines()

  # Find and replace the line for the specified post_type
  found = False
  for i, line in enumerate(lines):
    if line.startswith(f"{post_type}:"):
      lines[i] = new_log_entry
      found = True
      break

  # If the specified post_type is not found, append it to the end
  if not found:
    lines.append(new_log_entry)

  # Write back the updated content
  with open(log_file_path, "w") as log_file:
    log_file.writelines(lines)


#Example usage
log_current_time("Ransomware")
logger.info("Logging current time for ransomware")

#Get the current date
current_date = datetime.now().date()

#Create a new list to store filtered articles
filtered_list_ransomware = []

#Loop through the original list
for article_dict in raw_data_ransomware:
  # Extract the publish_date attribute
  publish_date_str = article_dict.get("publish_date", "")

  # Convert the publish_date string to a datetime object
  publish_date = datetime.strptime(publish_date_str,
                                   "%Y-%m-%d %H:%M:%S.%f").date()

  # Check if the publish_date is equal to the current date
  if publish_date == current_date:
    # Add the article to the filtered list
    filtered_list_ransomware.append(article_dict)

append_to_json(filtered_list_ransomware, "ransomware.json")
logger.info("Finished writing ransomware data")

logger.info("Querying private sector rss news")

raw_articles = []
for i in private_rss_feed_list:
  logger.info(f"Getting data from rss {i[1]}")
  articles_private = get_news_from_rss(i)
  for i in articles_private:
    raw_articles.append(format_single_article(i))

logger.info("Queried private sector rss news")
append_to_json(raw_articles, "private_rss.json")
logger.info("Saved private rss data")

#Example usage
log_current_time("Private feed")
logger.info("Logging current time for private sector")

logger.info("Querying government sector rss news")

raw_articles_gov = []
for i in gov_rss_feed_list:
  logger.info(f"Getting data from rss {i[1]}")
  articles_gov = get_news_from_rss(i)
  for i in articles_gov:
    raw_articles_gov.append(format_single_article(i))

logger.info("Queried government sector rss news")
append_to_json(raw_articles, "government_rss.json")
logger.info("Saved government rss data")

#Example usage
log_current_time("Government feed")
logger.info("Logging current time for Government sector")
