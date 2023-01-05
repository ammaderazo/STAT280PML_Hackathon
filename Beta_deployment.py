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
from PIL import Image

st.set_page_config(layout="wide")

headerIMG = Image.open('DetectifAI.jpg')
checkIMG = Image.open('checkmark.png')
detectedIMG = Image.open('frauddetected.png')

st.image(headerIMG)

#st.header("WebApp Deployment for Demo for PML Hackathon [Beta Ver.]")
#st.caption("WebApp Deployment for Demo for PML Hackathon [Beta Ver.]")

df = pd.read_csv('stopwords.csv')
stopwords = list(df['i'])

def fix_link(sms): 
    a = sms.replace(".", "")
    a = a.replace(",", "")
    a = a.split(" ")
    if ("com" in a):
        ind = a.index("com")
        print(ind)
        link = a[ind-1] + "." + a[ind]
        print(link)
        sms = sms + " " + link
    return sms

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
        result = pd.DataFrame() 
        return result
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
    result = result[0]
    return result 

sms = st.text_area("SMS/Email/Text to Investigate", key = "text")

col1, col2 = st.columns([10,1])

with col1:
    st.write("")
with col2:
    st.button("Clear Input", on_click = clear_text)

if st.button("Enter"):
    sms = " ".join(line.strip() for line in sms.splitlines())
    st.write(sms)
    sms = fix_link(sms)
    st.write(sms)
    sms_result = detect_fraud_sms(sms)
    url_result = detect_fraud_urls(sms)
    with st.spinner('Analyzing the Input'):
        time.sleep(5)
        st.success('SMS/Email/Text checked!!')

    try: 
        malicious_df = url_result[url_result['type'] == 'Malicious']
    except Exception:
        malicious_df = pd.DataFrame()

    if ((sms_result == 1) & (len(url_result) == 0)):
        col1, col2 = st.columns([1.5,2])
        with col1:  
            st.write(" ")
        with col2: 
            st.image(detectedIMG, width = 200)
            st.write("Malicious Activity Detected!")
           

    elif ((sms_result == 1) & (len(malicious_df) > 0)):
        col1, col2 = st.columns([1.5,2])
        with col1:
            st.write(" ")
        with col2:
            st.image(detectedIMG, width = 200)
            st.write("Malicious Activity Detected!")
   
        
        col3, col4 = st.columns([1.25,2])
        with col3:
            st.write(" ")
        with col4:
            st.write("List of detected malicious URLs:")
            st.write(malicious_df)
     
      
    elif ((sms_result == 0) & (len(malicious_df) > 0)):
        col1, col2 = st.columns([1.5,2])
        with col1: 
            st.write(" ")
        with col2: 
            st.image(detectedIMG, width = 200)
            st.write("Malicious Activity Detected!")
    
        
        col3, col4 = st.columns([1.25,2])
        with col3:
            st.write(" ")
        with col4:
            st.write("List of detected malicious URLs:")
            st.write(malicious_df)
         

    elif ((sms_result == 0) & ((len(malicious_df) == 0) | (len(url_result) == 0))):
        col1, col2, col3 = st.columns([2,2,1])
        with col1: 
            st.write(" ")
        with col2: 
            st.image(checkIMG)
            st.write("No Malicious Activity Detected")  
        with col3: 
            st.write(" ")

    st.button("Clear",on_click=restart)
