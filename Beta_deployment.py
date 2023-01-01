import dill 
import tldextract 
import pandas as pd 
import nltk
import pickle 
import warnings
warnings.filterwarnings("ignore")
from urlextract import URLExtract
extractor = URLExtract()
from urllib.request import urlopen
import streamlit as st
import time
import cloudpickle
import lightgbm
import re
 
st.set_page_config(layout="wide")
st.header("Fraud Detection Demo")
st.caption("WebApp Deployment for Demo for PML Hackathon [Beta Ver.]")

df = pd.read_csv('stopwords.csv')
stopwords = list(df['i'])

def clean_sms(df):
    df['text'] = df['text'].str.replace(r'^.+@[^\.].*\.[a-z]{2,}$', 'emailad')                                                      #replaces detected email address to "emailad"
    df['text'] = df['text'].str.replace(r'^http\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?$', 'url')                                 #replaces detected url to "url"
    df['text'] = df['text'].str.replace(r'£|\$', 'moneysym ')                                                                       #replace detected currency symbol to the string "money-sym"
    df['text'] = df['text'].str.replace(r'^\(?[\d]{3}\)?[\s-]?[\d]{3}[\s-]?[\d]{4}$', 'phone-num')                                  #replace detected phone number to the string "phone-num"
    df['text'] = df['text'].str.replace(r'\d+(\.\d+)?', 'num')                                                                      #replace detected number to the string "num"
    df['text'] = df['text'].str.replace(r'[^\w\d\s]', ' ')                                                                          #remove the punctuation 
    df['text'] = df['text'].str.replace(r'\s+', ' ')                                                                                #remove the whitespace between twems with single space
    df['text'] = df['text'].str.replace(r'^\s+|\s*?$', ' ')                                                                         #remove extra spaces before and after the texts
    df['text'] = df['text'].str.lower()                                                                                             #change the words to lower case 
    df['text'] = df['text'].apply(lambda x: ' '.join(term for term in x.split() if term not in stopwords))                          #remove stopwords such as the, an, a, in, but, because, etc...
    return df

format_url = pickle.load(open('URL_format_urls.pickle', 'rb'))
sms_detection = pickle.load(open('sms_fraud_mod.sav', 'rb'))
tfidf_model = pickle.load(open('tfidf_model.sav', 'rb'))
url_detection = pickle.load(open('urls_fraud_mod.sav', 'rb'))

def restart(): 
    st.session_state.page = 0
    st.session_state["text"] = " "

def clear_text(): 
    st.session_state["text"] = " "

#creating a function for detecting malicious link 
def detect_fraud_urls(sms): 
    url_list = extractor.find_urls(sms)
    if (len(url_list) == 0): 
        return "There are no urls in the sms"
    else: 
        for i in range(0,len(url_list)): 
            try: 
                url_list[i] = urlopen(url_list[i]).geturl() 
            except Exception:
                pass
        url_df = pd.DataFrame({'url': url_list})
        url_df = format_url(url_df)
        url_df = url_df.drop(['url'], axis=1)
        type = url_detection.predict(url_df)
        result = pd.DataFrame({'url': url_list , 'type':type})
        result['type']= result['type'].map({0: 'Benign', 1:'Malicious'})
        return result

#function for classifying the sms 
def detect_fraud_sms(sms):
    sms_df = pd.DataFrame({'text': [sms]})
    sms_df = clean_sms(sms_df)
    sms_df = tfidf_model.transform(sms_df)
    sms_df = pd.DataFrame(sms_df.toarray())
    result = sms_detection.predict(sms_df)
    #return result[0]
    if (result[0] == 0) :
        return "SMS is not a malicious/fraud"
    else:  
        return "SMS is a malicious/fraud"


    sms_result = detect_fraud_sms(sms)
    url_result = detect_fraud_urls(sms)
 



sms = st.text_area("SMS to Investigate", key = "text")

col1, col2 = st.columns([10,1])

with col1:
    if st.button("Enter"):
        sms_result = detect_fraud_sms(sms)
        url_result = detect_fraud_urls(sms)
        with st.spinner('Analyzing the SMS'):
            time.sleep(5)
            st.success('SMS checked!!')
            st.write(sms_result)
            st.write(url_result)
        #if ((sms_result == "SMS is not a malicious/fraud") & (url_result == "There are no urls in the sms")):
          #  st.write(sms)
          #  st.write("No malicious activity detected in the sms")
       # elif ((sms_result == "SMS is not a malicious/fraud") & (url_result != "There are no urls in the sms"))#: 
           # st.write("There are no malicious activity detected in the sms")
           # st.write("Here is a list and findings on the links included in the sms: ")
          #  st.write(url_result)
       # elif ((sms_result != "SMS is not a malicious/fraud") & (url_result == "There are no urls in the sms")): 
           # st.write("Malicious activity is detected with the sms")
       # elif ((sms_result != "SMS is not a malicious/fraud") & (url_result != "There are no urls in the sms")): 
       #     st.write("Malicious activity is detected with the sms")
       #     st.write("Here is a list and findings on the links included in the sms: ")
       #     st.write(url_result)
            
        st.button("Clear",on_click=restart)

with col2:
    st.button("Clear Text Input", on_click = clear_text)