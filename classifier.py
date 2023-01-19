# evaluate multinomial logistic regression model
from numpy import mean
from numpy import std
from sklearn.datasets import make_classification
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.linear_model import LogisticRegression
import pandas as pd
from sklearn.model_selection import StratifiedKFold, KFold
import time
from sklearn import metrics
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix, classification_report
from sklearn import svm
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier, AdaBoostRegressor
from sklearn.model_selection import train_test_split
from sklearn.inspection import permutation_importance
import pickle
import warnings
from sklearn.naive_bayes import GaussianNB
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF, DotProduct
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import MinMaxScaler
import os
import glob
from sklearn.metrics import roc_curve


warnings.filterwarnings("ignore", category=FutureWarning)
# define dataset


def feature_importance(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)
    #clf = svm.SVC(kernel='rbf', C = 10, random_state=0)
    clf = LogisticRegression(multi_class='multinomial', solver='lbfgs', C=0.4)
    #clf.fit(X_train, y_train)
    clf.fit(X, y)
    #plot_cm(clf, X_test, y_test)
    perm_importance = permutation_importance(
        clf, X, y, n_repeats=10, random_state=100)

    feature_names = ['rpki', 'score1', 'score2',
                     'score3', 'distance', 'hege_depth', 'path_len']
    #feature_names = [r'$Nwrap(x)$', r'$\overline{\Delta}(s)$', r'$\Delta _{max}(s)$', r'$\Delta _{max}(x)$', r'$\Delta _{max}(y)$','$Autocorr(s)$', '$B$','$F_{d}$', '$F_{rolloff}$']
    features = np.array(feature_names)

    sorted_idx = perm_importance.importances_mean.argsort()
    plt.rcParams["figure.figsize"] = (8, 5)
    font = {
        'weight': 'bold',
        'size': 14}
    plt.rc('font', **font)
    plt.barh(features[sorted_idx], perm_importance.importances_mean[sorted_idx], color=(
        158/256, 188/256, 218/256))
    plt.xlabel("Feature Importance", fontweight='bold')
    plt.subplots_adjust(left=0.25, top=0.90)
    plt.show()
    # plt.savefig("../images/feature_importance.pdf")


def plot_cm(clf, X_test, y_test):
    #classes = ['valid', 'misconf', 'route', 'hijacks']
    classes = ['valid', 'invalid']
    font = {
        'weight': 'bold',
        'size': 14}

    plt.rc('font', **font)
    plot_confusion_matrix(
        clf, X_test, y_test, display_labels=classes, cmap=plt.cm.Blues, normalize='true')
    plt.ylabel('True class', fontweight='bold')
    plt.xlabel('Predicted class', fontweight='bold')
    plt.subplots_adjust(left=0.2)
    plt.show()


def dt_cross_validation(f, X, y, d, l, m):
    accuracy = []
    precision = []
    recall = []
    f1_score = []
    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    # enumerate the splits and summarize the distributions
    for train_ix, test_ix in kfold.split(X, y):
        X_train, X_test = X[train_ix], X[test_ix]
        y_train, y_test = y[train_ix], y[test_ix]
        clf = DecisionTreeClassifier(
            max_depth=d, min_samples_leaf=l, random_state=0)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        #plot_cm(clf, X_test, y_test)
        accuracy.append(metrics.accuracy_score(y_test, y_pred))
        precision.append(metrics.precision_score(
            y_test, y_pred, average='macro'))
        recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
        f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))

    #print("Time cost:", np.mean(elps))
    print("Accuracy:", np.mean(accuracy))
    print("Precision:", np.mean(precision))
    print("Recall:", np.mean(recall))
    print("F1_score:", np.mean(f1_score))
    dt_classifier(X, y, d, l)
    accs = test_validate_data(m)
    f.write("d is {}, l is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {}t, Accs is {} \n".format(
        d, l, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score), accs))


def svm_cross_validation(f, X, y, c, m):
    accuracy = []
    precision = []
    recall = []
    f1_score = []
    #kfold = KFold(n_splits=10, shuffle=True, random_state=0)
    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    elps = []
    # enumerate the splits and summarize the distributions
    for train_ix, test_ix in kfold.split(X, y):
        X_train, X_test = X[train_ix], X[test_ix]
        y_train, y_test = y[train_ix], y[test_ix]
        #clf = LogisticRegression(multi_class='multinomial', solver=s, max_iter = 2000, C = c)
        clf = svm.SVC(kernel='rbf', C=c, random_state=0)
        #clf = DecisionTreeClassifier(max_depth=5, random_state=0)
        #clf = RandomForestClassifier(random_state=0)
        #clf = KNeighborsClassifier(n_neighbors=2)
        clf.fit(X_train, y_train)
        #plot_cm(clf, X_test, y_test)
        #end = time.monotonic()
        # elps.append(end-start)
        start = time.monotonic()
        y_pred = clf.predict(X_test)
        end = time.monotonic()
        elps.append(end-start)
        accuracy.append(metrics.accuracy_score(y_test, y_pred))
        precision.append(metrics.precision_score(
            y_test, y_pred, average='macro'))
        recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
        f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
        #cm = metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5])
    print("Time cost:", np.mean(elps))
    print("Accuracy:", np.mean(accuracy))
    print("Precision:", np.mean(precision))
    print("Recall:", np.mean(recall))
    print("F1_score:", np.mean(f1_score))
    svm_classifier(X, y, c)
    accs = test_validate_data(m)
    f.write(" C is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {}, Accs is {} \n".format(
        c, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score), accs))


def mlr_cross_validation(f, X, y, s, c, m):
    accuracy = []
    precision = []
    recall = []
    f1_score = []
    #kfold = KFold(n_splits=10, shuffle=True, random_state=0)
    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    elps = []
    # enumerate the splits and summarize the distributions
    for train_ix, test_ix in kfold.split(X, y):
        X_train, X_test = X[train_ix], X[test_ix]
        y_train, y_test = y[train_ix], y[test_ix]
        clf = LogisticRegression(
            multi_class='multinomial', solver=s, C=c)  # multinomial
        #clf = svm.SVC(kernel='rbf', C = 10, random_state=0)
        #clf = DecisionTreeClassifier(max_depth=5, random_state=0)
        #clf = RandomForestClassifier(random_state=0)
        #clf = KNeighborsClassifier(n_neighbors=2)
        clf.fit(X_train, y_train)
        #plot_cm(clf, X_test, y_test)
        #end = time.monotonic()
        # elps.append(end-start)
        start = time.monotonic()
        y_pred = clf.predict(X_test)
        end = time.monotonic()
        elps.append(end-start)
        accuracy.append(metrics.accuracy_score(y_test, y_pred))
        precision.append(metrics.precision_score(
            y_test, y_pred, average='macro'))
        recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
        f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
        #cm = metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5])

    print("Time cost:", np.mean(elps))
    print("Accuracy:", np.mean(accuracy))
    print("Precision:", np.mean(precision))
    print("Recall:", np.mean(recall))
    print("F1_score:", np.mean(f1_score))
    multiLR_classifier(X, y, s, c)
    accs = test_validate_data(m)
    f.write("Solver is {}, C is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {}, Accs is {} \n".format(
        s, c, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score), accs))


def dt_classifier(X, y, d, l):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)
    clf = DecisionTreeClassifier(
        max_depth=d, min_samples_leaf=l, random_state=0)
    start = time.time()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    end = time.time()
    print(end-start)

    with open('dt_classifier.pkl', 'wb') as f:
        pickle.dump(clf, f)

    #plot_cm(clf, X_test, y_test)
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))


def svm_classifier(X, y, c):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)  # 70% training and 30% test, stratify=y
    clf = svm.SVC(kernel='rbf', C=c, probability=True, random_state=0)
    start = time.time()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    end = time.time()
    print(end-start)

    with open('svm_classifier.pkl', 'wb') as f:
        pickle.dump(clf, f)
    #print(metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5]))
    #plot_cm(clf, X_test, y_test)
    print(classification_report(y_test, y_pred))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))


def multiLR_classifier(X, y, s, c):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)  # 70% training and 30% test, stratify=y
    # multi_class='multinomial', solver='lbfgs'
    clf = LogisticRegression(multi_class='multinomial', solver=s, C=c)
    #clf = DecisionTreeClassifier(max_depth=5, random_state=0)
    #clf = svm.SVC(kernel='rbf', C = 10, random_state=0)
    # clf = RandomForestClassifier(random_state=0) NOTE: the performance is same with DT
    # clf = KNeighborsClassifier(n_neighbors=2) NOTE: KNN is more complicate and too much time overhead, and cannot output probabilities
    start = time.time()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    end = time.time()
    print(end-start)
    with open('multiLR_classifier.pkl', 'wb') as f:
        pickle.dump(clf, f)

    #plot_cm(clf, X_test, y_test)
    print(classification_report(y_test, y_pred))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))


def test(X_test, y_test, pfxes, asIDs, ifile, ty, m):
    clf = None
    of = open('./BGPincidents/'+ty+'.error.res', 'w')
    with open(m+'_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    start = time.time()
    y_pred = clf.predict(X_test)
    end = time.time()
    print('time: ', (end-start)/len(X_test))
    a = np.array(y_pred)
    l = list()
    for i in range(len(a)):
        if y_test[i] != a[i]:
            l.append((pfxes[i], asIDs[i], y_test[i], a[i]))
            
    F = len(l)
    acc = metrics.accuracy_score(y_test, y_pred)
    #acc = metrics.precision_score(y_test, y_pred, average='macro')
    print('acc: ', acc)

    with open(ifile) as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            fields = line.split(',')
            pfx = fields[1]
            asID = fields[2]
            for t in l:
                if pfx == t[0] and asID == str(t[1]):
                    of.write(line+','+str(t[2])+','+str(t[3])+'\n')
    of.close()
    return acc, F


def test_proba(threshold):
    clf = None
    with open('./multiLR_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    FN, FP, TN, TP = 0, 0, 0, 0
    for ty in ['benign_misconfiguration', 'valid', 'route_leak', 'bgp_hijacks']:
        data = pd.read_csv('./ValidateData/'+ty+'.4f.csv', header=None)
        pfxes = data.iloc[:, 1].values
        X = data.iloc[:, 5:11].values
        if 'valid.' in ty:
            y = 1*np.ones(len(pfxes))
        elif 'benign' in ty:
            y = 2*np.ones(len(pfxes))
        elif 'route' in ty:
            y = 3*np.ones(len(pfxes))
        elif 'hijacks' in ty:
            y = 4*np.ones(len(pfxes))
        for i in range(len(y)):
            data = X[i, :]
            X_test = data.reshape(1, 6)
            y_pred = clf.predict_proba(X_test)
            benign = y_pred[0][0]+y_pred[0][1]
            malicious = y_pred[0][2] + y_pred[0][3]
            if malicious >= threshold:
                y_pred = 1
            else:
                y_pred = 0
            if y[i] in [3.0, 4.0]:
                y_expe = 1
            elif y[i] in [1.0, 2.0]:
                y_expe = 0
            if y_expe == 0 and y_pred == 0:
                TN = TN + 1
            elif y_expe == 0 and y_pred == 1:
                FP = FP + 1
            elif y_expe == 1 and y_pred == 0:
                FN = FN + 1
            elif y_expe == 1 and y_pred == 1:
                TP = TP + 1
    fpr = FP/(FP+TN)
    fnr = FN/(FN+TP)
    tpr = TP/(TP+FN)
    tnr = TN/(TN+FP)
    print(fpr, fnr, tpr, tnr)


def mlr_grid_searching(X, y, n):
    m = 'multiLR'
    f = open('./GridSearch/mlr_grid_search.'+str(n)+'.2f.res', 'w')
    # for s in ['newton-cg', 'lbfgs', 'sag', 'saga']:
    s = 'lbfgs'
    for c in range(2, 21, 1):
        c = c/20
        mlr_cross_validation(f, X, y, s, c, m)
    f.close()


def svm_grid_searching(X, y, n):
    m = 'svm'
    f = open('./GridSearch/svm_grid_search.'+str(n)+'.2f.res', 'w')
    c_degrees = [1, 10, 50, 100, 200, 400, 600, 800, 1000, 10000]
    for c in c_degrees:
        svm_cross_validation(f, X, y, c, m)
    f.close()


def dt_grid_searching(X, y, n):
    m = 'dt'
    f = open('./GridSearch/dt_grid_search.'+str(n)+'.2f.res', 'w')
    for d in range(3, 10, 2):
        for l in range(2, 20, 2):
            dt_cross_validation(f, X, y, d, l, m)
    f.close()


def test_bgp_incidents(m):
    accs = []
    file_path = './BGPincidents'
    files = os.path.join(file_path, "route_leak.*.4f.csv")
    files = glob.glob(files)
    ntotal = 0
    nerr = 0
    for ifile in files:
        ty = ifile.split('/')[-1]
        print(ty)
        data = pd.read_csv(ifile)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values
        #X = data.iloc[:, 5:10].values
        X = data.iloc[:, 5:7].values
        Dis = data.iloc[:, 8].values.reshape(len(pfxes), 1)
        valley_score = []
        for i in data.iloc[:, 7].values:
            if i == 1.0:
                i = 0.5
            valley_score.append(i)
        Path = (valley_score + data.iloc[:, 9].values).reshape(len(pfxes), 1)
        X = np.concatenate((X, Dis, Path), axis=1)
        n = 0
        if 'valid' in ty:
            n = 1
        elif 'benign' in ty:
            n = 1
        elif 'route' in ty:
            n = 2
        elif 'hijacks' in ty:
            n = 2
        y = n*np.ones(len(pfxes))
        # Need to update the file name
        acc, F = test(X, y, pfxes, asIDs, ifile, ty, m)
        print('num: ', len(y))
        ntotal = ntotal + len(y)
        nerr = nerr + F
        accs.append(acc)
    print('acc of route leak: ', (ntotal-nerr)/ntotal)
    return accs

def test_bgp_incidents(m):
    accs = []
    file_path = './BGPincidents'
    files = os.path.join(file_path, "route_leak.*.4f.csv")
    files = glob.glob(files)
    ntotal = 0
    nerr = 0
    print(len(files))
    for ifile in files:
        ty = ifile.split('/')[-1]
        
        data = pd.read_csv(ifile)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values
        X = data.iloc[:, 5:9].values
        
        n = 0
        if 'valid' in ty:
            n = 1
        elif 'benign' in ty:
            n = 1
        elif 'leak' in ty:
            n = 2
        elif 'hijacks' in ty:
            n = 2
        y = n*np.ones(len(pfxes))
        # Need to update the file name
        acc, F = test(X, y, pfxes, asIDs, ifile, ty, m)
        print('num: ', len(y))
        ntotal = ntotal + len(y)
        nerr = nerr + F
        accs.append(acc)
    print('acc of route leak: ', (ntotal-nerr)/ntotal)
    return accs


def test_validate_data(m):
    nums = []
    accs = []
    errs = []
    for ty in ['valid', 'benign_misconfiguration', 'route_leak', 'bgp_hijacks']:
        ifile = './ValidateData/'+ty+'.4f.csv'  # benign_misconfiguration.validate
        data = pd.read_csv(ifile)  # header = None
        pfxes = data.iloc[:, 1].values
        asIDs = data.iloc[:, 2].values
        #X = data.iloc[:, 5:10].values
        X = data.iloc[:, 5:7].values
        Dis = data.iloc[:, 8].values.reshape(len(pfxes), 1)
        valley_score = []
        for i in data.iloc[:, 7].values:
            if i == 1.0:
                i = 0.5
            valley_score.append(i)
        Path = (valley_score + data.iloc[:, 9].values).reshape(len(pfxes), 1)
        X = np.concatenate((X, Dis, Path), axis=1)
        n = 0
        if 'valid' in ty:
            n = 1
        elif 'benign' in ty:
            n = 1
        elif 'route' in ty:
            n = 2
        elif 'hijacks' in ty:
            n = 2
        y = n*np.ones(len(pfxes))
        # Need to update the file name
        acc, F = test(X, y, pfxes, asIDs, ifile, ty, m)
        errs.append(F)
        accs.append(acc)
        nums.append(len(y))
    print(1-(errs[0]+errs[1])/(nums[0]+nums[1]),
          1-(errs[2]+errs[3])/(nums[2]+nums[3]))
    return accs, errs, nums

    # feature_importance(X,y)
    # test_proba(0.20) # search a threshold in [0.5, 0.45, 0.4, 0.35, 0.3]
    '''
	model = LogisticRegression(multi_class='multinomial', solver='lbfgs')
	model.fit(X, y)
	row = [0,0,0,0,0.0,0.0] #1,1,1,1,1,-1,1,0.0
	yhat = model.predict_proba([row])
	print('Predicted Class: %s' % yhat[0])
	'''

    '''
	X = data.iloc[:,5:8].values
	print(X.shape)
	Di = data.iloc[:,9].values.reshape(len(pfxes), 1)
	print(Di.shape)
	De = (((-1)*data.iloc[:,8].values + data.iloc[:,10].values)/2).reshape(len(pfxes), 1)
	print(De.shape)
	Xnew = np.concatenate((X, Di, De), axis = 1)
	'''


def plot_auc_roc(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)  # 70% training and 30% test, stratify=y
    clf1 = svm.SVC(kernel='rbf', C=10, probability=True, random_state=0)
    clf2 = DecisionTreeClassifier(
        max_depth=3, min_samples_leaf=2, random_state=0)
    clf3 = LogisticRegression(multi_class='multinomial', solver='lbfgs', C=1)
    clf1.fit(X_train, y_train)
    clf2.fit(X_train, y_train)
    clf3.fit(X_train, y_train)
    pred_prob1 = clf1.predict_proba(X_test)
    pred_prob2 = clf2.predict_proba(X_test)
    pred_prob3 = clf3.predict_proba(X_test)
    # skplt.metrics.plot_roc_curve(y_test-1, pred_prob1,
    # title="ROC Curve", figsize=(12,6))

    print(pred_prob1[:, 1], y_test-1)
    fpr1, tpr1, thresh1 = roc_curve(y_test-1, pred_prob1[:, 1], pos_label=1)
    fpr2, tpr2, thresh2 = roc_curve(y_test-1, pred_prob2[:, 1], pos_label=1)
    fpr3, tpr3, thresh3 = roc_curve(y_test-1, pred_prob3[:, 1], pos_label=1)

    random_probs = [0 for i in range(len(y_test))]
    p_fpr, p_tpr, _ = roc_curve(y_test, random_probs, pos_label=1)

    # plot roc curves
    plt.plot(fpr1, tpr1, linestyle='--', color='orange', label='SVM')
    #plt.plot(fpr2, tpr2, linestyle='--',color='green', label='DT')
    #plt.plot(fpr3, tpr3, linestyle='--',color='blue', label='Logistic Regression')
    plt.plot(p_fpr, p_tpr, linestyle='--', color='black')
    # title
    plt.title('ROC curve')
    # x label
    plt.xlabel('False Positive Rate')
    # y label
    plt.ylabel('True Positive rate')

    # plt.legend(loc='best')
    plt.savefig('ROC', dpi=300)
    plt.show()

