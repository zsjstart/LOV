
from numpy import mean
from numpy import std

from sklearn.model_selection import RepeatedStratifiedKFold

import pandas as pd
from sklearn.model_selection import StratifiedKFold, KFold
import time
from sklearn import metrics
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix, classification_report

from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor

from sklearn.model_selection import train_test_split
from sklearn.inspection import permutation_importance
import pickle
import warnings
import os
import glob

from sklearn.preprocessing import MinMaxScaler, StandardScaler
from imblearn.over_sampling import RandomOverSampler, SMOTE, ADASYN

import joblib


def construct_new_features(X, save):
    # split X into individual columns
    f1 = X[:, 0]  # first column
    f2 = X[:, 1]  # second column
    f3 = X[:, 2]  # third column
    f4 = X[:, 3]  # fourth column
    f5 = X[:, 4]  # fifth column
    f6 = X[:, 5]  # sixth column
    f7 = X[:, 6]
    a, b, c, d, e, f = 1, 1, 1.0, 0.2, 0.3, 0.6
    

    fagg = a*f1+b*f2+c*f3+d*f4+e*f5+f*f6
    fagg = fagg.reshape(-1, 1)
    X = np.concatenate((fagg, f7.reshape(-1, 1)), axis=1)
    if save:
        save_scaler(X)
    return X

def dt_cross_validation(f, X, y, d, l, m):
    accuracy = []
    precision = []
    recall = []
    f1_score = []
    kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
    # enumerate the splits and summarize the distributions
    for train_ix, test_ix in kfold.split(X, y):
        X_train, X_test = X[train_ix], X[test_ix]
        y_train, y_test = y[train_ix], y[test_ix]
        clf = DecisionTreeClassifier(
            max_depth=d, min_samples_leaf=l, random_state=3)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        #plot_cm(clf, X_test, y_test)
        accuracy.append(metrics.accuracy_score(y_test, y_pred))
        precision.append(metrics.precision_score(
            y_test, y_pred, average='macro'))
        recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
        f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
    '''
    #print("Time cost:", np.mean(elps))
    print("Accuracy:", np.mean(accuracy))
    print("Precision:", np.mean(precision))
    print("Recall:", np.mean(recall))
    print("F1_score:", np.mean(f1_score))
    #dt_classifier(X, y, d, l)
    #accs = test_validate_data(m)
    '''
    f.write("d is {}, l is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {}, \n".format(d, l, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score)))

    return np.mean(accuracy)

def dt_grid_searching(X, y):
    m = 'dt'
    f = open('./GridSearch/dt_grid_search.7f.res', 'w')
    for d in range(3, 20, 1):
        for l in range(2, 20, 2):
            dt_cross_validation(f, X, y, d, l, m)
    f.close()

def dt_classifier(X, y, d, l):

    clf = DecisionTreeClassifier(
        max_depth=d, min_samples_leaf=l, random_state=0)

    clf.fit(X, y)

    start = time.time()

    importances = clf.feature_importances_
    for feature, importance in zip(['Confidence', 'Distance'], importances):
        print("{}: {}".format(feature, importance))

    end = time.time()
    print(end-start)

    with open('dt_classifier.pkl', 'wb') as f:
        pickle.dump(clf, f)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=3, stratify=y)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    plot_cm(clf, X_test, y_test)
    #print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    return metrics.accuracy_score(y_test, y_pred)

def get_weights(X, y):
    # split X into individual columns
    f1 = X[:, 0]  # first column
    f2 = X[:, 1]  # second column
    f3 = X[:, 2]  # third column
    f4 = X[:, 3]  # fourth column
    f5 = X[:, 4]  # fifth column
    f6 = X[:, 5]  # sixth column
    f7 = X[:, 6]

    a = 1
    c = 1
    accs = []
    for b in np.arange(0, 1.1, 0.1):
        for d in np.arange(0, 1.1, 0.1):
            for e in np.arange(0, 1.1, 0.1):
                for f in np.arange(0, 1.1, 0.1):
                    fagg = a*f1+b*f2+c*f3+d*f4+e*f5+f*f6
                    fagg = fagg.reshape(-1, 1)
                    X = np.concatenate((fagg, f7.reshape(-1, 1)), axis=1)
                    scaler = StandardScaler()
                    scaler.fit(X)
                    X = scaler.transform(X)
                    #acc = dt_classifier(X, y, d=9, l=2)
                    #accs.append((acc, a, b, c, d, e, f))

                    for m in range(3, 10, 2):
                        for n in range(2, 20, 2):
                            acc = dt_cross_validation(None, X, y, m, n, 'dt')
                            accs.append((acc, a, b, c, d, e, f, m, n))

    
    accs.sort(key=lambda a: a[0])
    print(accs[-20:])
    d, e, f = set(), set(), set()
    for v in accs:
        acc = v[0]
        if acc == accs[-1][0]:
            d.add(v[4])
            e.add(v[5])
            f.add(v[6])
    print(d, e, f)
    print(sum(d)/len(d), sum(e)/len(e), sum(f)/len(f))


def test(X_test, y_test, pfxes, asIDs, m, ifile, ofile):
    clf = None
    with open(m+'_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    start = time.time()
    y_pred = clf.predict(X_test)
    end = time.time()
    #print('time: ', (end-start)/len(X_test))
    a = np.array(y_pred)
    l = list()
    for i in range(len(a)):
        if y_test[i] != a[i]:
            l.append((pfxes[i], asIDs[i], y_test[i], a[i]))

    F = len(l)
    acc = metrics.accuracy_score(y_test, y_pred)
    #acc = metrics.precision_score(y_test, y_pred, average='macro')

    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            fields = line.split(',')
            pfx = fields[1]
            asID = fields[2]
            for t in l:
                if pfx == t[0] and asID == str(t[1]):
                    ofile.write(line+','+str(t[2])+','+str(t[3])+'\n')

    return acc, F

def test_validate_data(m):
    nums = []
    accs = []
    errs = []
    ofile = open('./GroundtruthData/holdout_errs.res', 'w')
    for ty in ['benign_conflict']:
        ifile = './GroundtruthData/'+ty + \
            '.holdout.csv'  # benign_misconfiguration.validate
        data = pd.read_csv(ifile)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values

        X = data.iloc[:, 3:10].values
        X = construct_new_features(X, False)
        scaler = joblib.load('./dt_scaler.gz')
        X = scaler.transform(X)
        y = 1*np.ones(len(pfxes))
        acc, F = test(X, y, pfxes, asIDs, m, ifile, ofile)
        errs.append(F)
        accs.append(acc)
        nums.append(len(y))
    print(accs, errs, nums)
    ofile.close()
    return accs[0]


def test_bgp_hijacks(m):
    accs = []
    file_path = './GroundtruthData/hijack_events'
    files = os.path.join(file_path, "bgp_hijack.*.csv")
    files = glob.glob(files)
    ntotal = 0
    nerr = 0
    ofile = open(file_path + '/hijacks_errs.res', 'w')
    for ifile in files:
        ty = ifile.split('/')[-1]
        # if '20210416' in ty:
        #    continue
        print(ty)
        data = pd.read_csv(ifile)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values
        #X = data.iloc[:, 5:10].values
        X = data.iloc[:, 3:10].values
        X = construct_new_features(X, False)
        scaler = joblib.load('./dt_scaler.gz')
        X = scaler.transform(X)
        y = 2*np.ones(len(pfxes))
        # Need to update the file name

        acc, F = test(X, y, pfxes, asIDs, m, ifile, ofile)
        print('acc: ', acc)
        print('number: ', len(y))
        ntotal = ntotal + len(y)
        
        nerr = nerr + F
        accs.append(acc)
    print('total hijacks: ', ntotal)
    print('total error: ', nerr)
    print('acc of bgp hijack: ', (ntotal-nerr)/ntotal)
    ofile.close()
    return (ntotal-nerr)/ntotal

def main():

    acc = list()
    for i in range(20, 21): 
        ifile = './GroundtruthData/202303/all_features.mini.csv'
        data = pd.read_csv(ifile, header=None)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values
        X = data.iloc[:, 3:10].values
        y = data.iloc[:, 10].values
	
	#get_weights(X, y)
        oversample = RandomOverSampler(
            sampling_strategy='minority', random_state=i)  # 9: maximum
        X, y = oversample.fit_resample(X, y)
        
        
        X = construct_new_features(X, True)
        scaler = joblib.load('./dt_scaler.gz')
        X = scaler.transform(X)
        dt_classifier(X, y, d=11, l=2)
        #dt_grid_searching(X, y)
        
        acc.append((test_validate_data('dt'), test_bgp_hijacks('dt'), i))
        
        
        
        
    print(acc)


if __name__ == "__main__":
    # execute only if run as a script
    main()
