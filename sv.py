import pandas as pd
import sweetviz as sv
from sklearn.model_selection import train_test_split

df = pd.read_csv("data.csv")

report = sv.analyze(df)
report.show_html("report.html")