import streamlit as st 

st.set_page_config(layout="wide")
st.header("Fraud Detection Demo")
st.caption("WebApp Deployment for Demo for PML Hackathon [Beta Ver.]")
sms = st.text_area("SMS to Investigate")
sms = type(sms)
st.write(sms)