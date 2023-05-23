#!/usr/bin/env python
# coding: utf-8

# 1. K-means 클러스터링
#  - 데이터를 k-means 클러스터링 알고리즘으로 그룹화한다.
#  - 클러스터링 한 데이터를 이중 분류 또는 다중 분류 알고리즘에 적합한 형식으로 변환한다.
# 2. 변환한 데이터를 다음 알고리즘에 따라 분류 한다
#  - 이중 분류 알고리즘: 나이브 베이즈, 인공신경망
#  - 다중 분류 알고리즘: 나이브 베이즈, 다중 클래스 신경망
# 3. 모델을 딥러닝시킨다.
#  - cnn 컨볼루션 신경망

# # Network Intrusion System 
# 네트워크 탐지 시스템 구현을 위한 아키텍쳐는 다음과 같다.
# <p align="center"><img src=image\flowchart.png width="600" height="200"/>

# ### Data Set
# 데이터 셋은 NSL-KDD를 사용한다. NSL- KDD는 다음과 같은 4가지의 공격 종류를 가진다.
# <p align="center"><img src=image/AttackType.png width="400" height="200"/>
# 
# 위의 데이터 셋에는 단순한 침입 탐지 네트워크에서 볼 수 있는 인터넷 트래픽의 기록이 포함되어 있으며, 실제 IDS에서 마주치는 트래픽의 유형이며 존재의 흔적만이 남아있다. 
# 
# 데이터 셋에는 기록 당 43가지의 특징을 가지고 있으며, 이 중 41개의 특징은 트래픽 입력 자체를 참조하여 마지막 2개는 레이블(노말 또는 공격)과 점수(트래픽 입력 자체의 심각도)이다.

# In[10]:


# importing Library
#module imports
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import itertools
import random 

#model imports


#processing imports
from sklearn.decomposition import PCA
from sklearn.preprocessing import RobustScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.metrics import mean_absolute_error
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix


# # Data Extraction
# - 공격자에 대한 특징을 추출하기 위해 nsl-kdd 데이터 살펴볼 것

# In[11]:


# fetch the training file
file_path_20_percent = './nsl-kdd/KDDTrain+_20Percent.txt'
file_path_full_training_set = './nsl-kdd/KDDTrain+.txt'
file_path_test = './nsl-kdd/KDDTest+.txt' 

#df = pd.read_csv(file_path_20_percent)
df = pd.read_csv(file_path_full_training_set)
test_df = pd.read_csv(file_path_test)


# In[12]:


#데이터에는 열에 대한 정보가 없기 때문에, 이것을 정의하여 데이터를 잘 정리할 수 있도록 한다. 
columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot'
,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','outcome','level'])

df.columns = columns
test_df.columns = columns

# sanity check
df.head()


# 데이터를 분류할 때 normal & Attack 로 이진 분류를 하는 것과 Iris 데이터 셋과 같은 결과가 여러가지인 다중 분류가 있다. 
# 
# 따라서 처음에는 normal & Attack 결과로 나오는 이진 분류로 도출하고 이후에는  DOS,Probe,U2R,R2L 결과를 도출해내는 다중 분류를 도출한다.

# # Preprocessing

# In[13]:


def Scaling(df_num, cols):
    std_scaler = RobustScaler()
    std_scaler_temp = std_scaler.fit_transform(df_num)
    std_df = pd.DataFrame(std_scaler_temp, columns =cols)
    return std_df


# In[14]:


cat_cols = ['is_host_login','protocol_type','service','flag','land', 'logged_in','is_guest_login', 'level', 'outcome']
def preprocess(dataframe):
    df_num = dataframe.drop(cat_cols, axis=1)
    num_cols = df_num.columns
    scaled_df = Scaling(df_num, num_cols)
    
    dataframe.drop(labels=num_cols, axis="columns", inplace=True)
    dataframe[num_cols] = scaled_df[num_cols]
    
    dataframe.loc[dataframe['outcome'] == "normal", "outcome"] = 0
    dataframe.loc[dataframe['outcome'] != 0, "outcome"] = 1
    
    dataframe = pd.get_dummies(dataframe, columns = ['protocol_type', 'service', 'flag'])
    return dataframe


# In[15]:


scaled_train = preprocess(df)


# # Data Scaling
#  PCA 기법을 사용해서 데이터 차원을 줄인 뒤 nsl-kdd 의 데이터셋 특성을 적절하게 선택하고 전처리할 수 있도록 한다.

# In[16]:


x = scaled_train.drop(['outcome', 'level'] , axis = 1).values
y = scaled_train['outcome'].values
y_reg = scaled_train['level'].values

pca = PCA(n_components=20)
pca = pca.fit(x)
x_reduced = pca.transform(x)
print("Number of original features is {} and of reduced features is {}".format(x.shape[1], x_reduced.shape[1]))

y = y.astype('int')
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
x_train_reduced, x_test_reduced, y_train_reduced, y_test_reduced = train_test_split(x_reduced, y, test_size=0.2, random_state=42)
x_train_reg, x_test_reg, y_train_reg, y_test_reg = train_test_split(x, y_reg, test_size=0.2, random_state=42)


# # Clustering

# In[ ]:




