import streamlit as st
import pymongo
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import requests

# Load environment variables
load_dotenv()
client = MongoClient(os.getenv('MONGO_URI'))
db = client["manychat_automation"]
collection = db["automation_rules"]

# Function to handle authentication with Meta's Graph API
def authenticate_with_facebook():
    auth_url = "https://www.facebook.com/v21.0/dialog/oauth"
    redirect_url = "YOUR_REDIRECT_URI_HERE"
    client_id = os.getenv('FACEBOOK_CLIENT_ID')
    scope = "pages_manage_posts,pages_show_list,pages_read_engagement"
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_url,
        "scope": scope,
        "response_type": "code"
    }
    
    st.markdown(f'<a href="{auth_url}?{requests.compat.urlencode(auth_params)}" target="_self">Login with Business Manager</a>', unsafe_allow_html=True)
    
    if 'code' in st.experimental_get_query_params():
        code = st.experimental_get_query_params()['code'][0]
        access_token_url = "https://graph.facebook.com/v21.0/oauth/access_token"
        token_params = {
            "client_id": client_id,
            "redirect_uri": redirect_url,
            "client_secret": os.getenv('FACEBOOK_CLIENT_SECRET'),
            "code": code
        }
        response = requests.get(access_token_url, params=token_params)
        if response.status_code == 200:
            access_token = response.json()['access_token']
            st.session_state['access_token'] = access_token
            st.success('Successfully authenticated!')
        else:
            st.error('Authentication failed.')

# Main app
def main():
    st.title("ManyChat Automation with MongoDB and Streamlit")
    
    if 'access_token' not in st.session_state:
        authenticate_with_facebook()
    else:
        st.write("Logged in successfully.")
        
        # Store API credentials
        api_keys = st.text_input("Enter your API keys and credentials", type="password")
        if st.button("Save API Keys"):
            if api_keys:
                collection.update_one({"_id": "api_keys"}, {"$set": {"keys": api_keys}}, upsert=True)
                st.success("API keys saved to database.")
            else:
                st.error("Please enter API keys.")

        # Create new automation
        st.subheader("Create New Automation")
        trigger_type = st.selectbox("Choose Trigger Type", ["Comment", "DM", "Story Reply"])
        trigger_word = st.text_input("Enter Trigger Word")
        
        if st.button("Define Trigger"):
            new_rule = {
                "trigger_type": trigger_type,
                "trigger_word": trigger_word
            }
            result = collection.insert_one(new_rule)
            st.success(f"New automation rule added with ID: {result.inserted_id}")
        
        # Define message content
        st.subheader("Define Message Content")
        message_type = st.selectbox("Message Type", ["Text Only", "Text with Button"])
        message_text = st.text_area("Message Content")
        
        if message_type == "Text with Button":
            button_text = st.text_input("Button Text")
            button_action = st.text_input("Button Action URL or Payload")
        
        if st.button("Save Message"):
            if message_type == "Text Only":
                message = {"type": "text", "content": message_text}
            else:
                message = {
                    "type": "text_with_button", 
                    "content": message_text, 
                    "button_text": button_text,
                    "button_action": button_action
                }
            collection.update_one({"trigger_word": trigger_word}, {"$set": {"message": message}})
            st.success(f"Message for trigger '{trigger_word}' saved.")

        # Display rules
        st.subheader("Current Automation Rules")
        rules = list(collection.find({}))
        for rule in rules:
            if rule.get('_id') != 'api_keys':  # Skip the API keys entry
                st.write(f"**Trigger Type:** {rule['trigger_type']}, **Trigger Word:** {rule['trigger_word']}")
                if rule.get('message'):
                    if rule['message']['type'] == 'text':
                        st.write(f"- Message: {rule['message']['content']}")
                    elif rule['message']['type'] == 'text_with_button':
                        st.write(f"- Message: {rule['message']['content']}")
                        st.write(f"- Button Text: {rule['message']['button_text']}")
                        st.write(f"- Button Action: {rule['message']['button_action']}")

if __name__ == "__main__":
    main()
