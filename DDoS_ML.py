import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.impute import SimpleImputer

#Extract features
def feature_extraction():
    #Open CSV and remove features that are irrelevant (ip addresses will be different in real life)
    df = pd.read_csv("dataset_sdn.csv")
    df.drop(["src", "dst"], axis=1, inplace=True)

    #Convert categorical data to numerical
    encoder = LabelEncoder()
    df["Protocol"] = encoder.fit_transform(df["Protocol"])

    #This dataset contained some missing values, fill in the values with the most frequent value around it
    imp = SimpleImputer(missing_values=np.nan, strategy='most_frequent')
    df = imp.fit_transform(df)

    #seperate label from features
    y = df[:,-1]
    x = df[:,:-1]

    #Split the data for training and testing at a ration of 80/20
    xTrain, xTest, yTrain, yTest = train_test_split(x, y, test_size=0.2, random_state=42)

    return xTrain, xTest, yTrain, yTest


def log_reg(xTrain, yTrain, xTest, yTest):
    classifier = LogisticRegression(max_iter = 10000)
    classifier.fit(xTrain, yTrain)

    pred = classifier.predict(xTest)

    accuracy = accuracy_score(yTest, pred)
    print("Accuracy of logistic regression:", accuracy)
    return accuracy

def random_forest(xTrain, yTrain, xTest, yTest):
    classifier = RandomForestClassifier(n_estimators=100)
    classifier.fit(xTrain, yTrain)

    pred = classifier.predict(xTest)

    accuracy = accuracy_score(yTest, pred)
    print("Accuracy of random forest:", accuracy)
    return accuracy

def find_best_k(xTrain, yTrain, xTest, yTest):
    k_range = range(1, 18)
    k_scores = []

    for k in k_range:
        classifier = KNeighborsClassifier(n_neighbors=k)
        classifier.fit(xTrain, yTrain)

        pred = classifier.predict(xTest)

        score = accuracy_score(yTest, pred)
        k_scores.append(score)
    
    best_k = k_scores.index(max(k_scores)) + 1
    return best_k

def knn(xTrain, yTrain, xTest, yTest, best_k):
    classifier = KNeighborsClassifier(n_neighbors = best_k)
    classifier.fit(xTrain, yTrain)

    pred = classifier.predict(xTest)

    accuracy = accuracy_score(yTest, pred)
    print("Accuracy of KNN:", accuracy)
    return accuracy




xTrain, xTest, yTrain, yTest= feature_extraction() #get data



#Find accuracy of each algorithm
best_k = find_best_k(xTrain, yTrain, xTest, yTest)
log_reg_acc = log_reg(xTrain, yTrain, xTest, yTest)
random_forest_acc = random_forest(xTrain, yTrain, xTest, yTest)
knn_acc = knn(xTrain, yTrain, xTest, yTest, best_k)