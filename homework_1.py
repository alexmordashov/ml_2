from selenium import webdriver
import pandas as pd
from bs4 import BeautifulSoup

driver = webdriver.Chrome()


def get_index_html(index_html):
    driver.get(index_html)
    page_content = driver.page_source
    bs = BeautifulSoup(page_content, "html.parser")
    return [i.text for i in bs.find_all("li")]


def parse_page(index_html):
    driver.get(index_html)
    page_content = driver.page_source
    bs = BeautifulSoup(page_content, "html.parser")
    table = bs.find("table", {"id": "Malicious"})
    headers = table.find("thead")
    headers_table = [i.text for i in headers.find_all("th")]
    bodies = table.find("tbody")
    bodies_table = []
    for i in bodies.find_all("tr"):
        bodies_items = [j.text for j in i.find_all("td")]
        bodies_table.append(bodies_items)
    return headers_table, bodies_table


urls = get_index_html("https://ratcatcher.ru/media/summer_prac/parcing/2/index.html")
headers = None
all_bodies = []
for i in urls:
    headers, bodies = parse_page(i)
    all_bodies.extend(bodies)
df = pd.DataFrame(all_bodies, columns=headers)
csv_data = df.to_csv(index=False, encoding='cp1251', lineterminator='\n').strip()
with open("data.csv", 'w') as f:
    f.write(csv_data)
