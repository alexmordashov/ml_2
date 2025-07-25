'''import re

#Проверьте, начинается ли строка с «The» и заканчивается ли она на «Spain»:

txt = "The rain in Spain"
x = re.search("^The.*Spain$", txt)

if x:
  print("Есть совпадение")
else:
  print("Нет совпадения")'''

'''import re

p = re.compile('https:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/[a-zA-Z0-9]+)?', flags=0)
string = 'Ссылка: https://test.ru/page, Тип: веб'
result = re.findall(p, string)

print(result)'''

'''import re

p = re.compile('+/g', flags=0)
string = 'Ссылка: https://test.ru/page, Тип: веб'
result = re.findall(p, string)

print(result)'''

'''from bs4 import BeautifulSoup
with open('1.html', 'r') as file:
    content = file.read()
soup = BeautifulSoup(content, "html.parser")
for child in soup.descendants:
    if child.name:
        print(child.name)'''