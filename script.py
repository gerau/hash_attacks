import pandas as pd
import sys
from scipy import stats
from math import sqrt

df = pd.read_csv("build/results.csv")

print(df)

alpha = 0.95

for column in df.columns:
    print(f"statistics for {column}:")
    print(f"    mean:{df[column].mean()}")
    print(f"    standard variance:{df[column].var()}")
    print(f"    standard deviation:{df[column].std()}")
    N = df[column].count()
    q = stats.t(df=N - 1).ppf(1 - (1 - alpha) / 2)
    X, S = df[column].mean(), df[column].std()
    left, right = X - q * S / sqrt(N), X + q * S / sqrt(N)
    print(f"    confidence interval = ({left},{right})")
