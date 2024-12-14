import streamlit as st
import pymongo
import requests
import json
import uuid
from bson.objectid import ObjectId
from datetime import datetime

# MongoDB Setup
MONGO_URI = "mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority"
client = pymongo.MongoClient(MONGO_URI)
db = client["automation_system"]
automations = db["automations"]  # Collection for automation rules

# Meta API Endpoints
GRAPH_API_BASE = "https://graph.facebook.com/v21.0"

# Securely store access tokens (use environment variables in production)
st.session_state.setdefault("access_token", None)
st.session_state.setdefault("page_id", None)
st.session_state.setdefault("instagram_id", None)

# Streamlit App Configuration
st.set_page_config(page_title="Instagram DM Automation", layout="wide")

# Login Section
def login():
    st.title("Login with Facebook Business")

    if "access_token" not in st.session_state or not st.session_state.access_token:
        client_id = "<your_app_id>"
        redirect_uri = "https://localhost/"
        auth_url = f"https://www.facebook.com/v21.0/dialog/oauth?client_id={client_id}&redirect_uri={redirect_uri}&scope=pages_manage_metadata,pages_messaging,instagram_manage_comments"

        st.markdown(f"[Login with Facebook]({auth_url})")
        token_input = st.text_input("Enter Access Token:")

        if token_input:
            st.session_state.access_token = token_input
            fetch_page_and_instagram_ids()
            st.success("Logged in successfully!")

# Fetch Page and Instagram IDs
def fetch_page_and_instagram_ids():
    headers = {"Authorization": f"Bearer {st.session_state.access_token}"}
    pages_url = f"{GRAPH_API_BASE}/me/accounts"
    response = requests.get(pages_url, headers=headers)

    if response.status_code == 200:
        pages = response.json().get("data", [])
        if pages:
            st.session_state.page_id = pages[0]["id"]
            instagram_url = f"{GRAPH_API_BASE}/{st.session_state.page_id}?fields=instagram_business_account"
            insta_response = requests.get(instagram_url, headers=headers)

            if insta_response.status_code == 200:
                st.session_state.instagram_id = insta_response.json().get("instagram_business_account", {}).get("id")

# Save Automation to Database
def save_automation(data):
    data["created_at"] = datetime.utcnow()
    automations.insert_one(data)
    st.success("Automation rule created successfully!")

# Create Automation Section
def create_automation():
    st.title("Create New Automation")

    if not st.session_state.access_token:
        st.error("You must log in first.")
        return

    # Select Trigger
    st.subheader("Trigger Type")
    trigger_type = st.selectbox(
        "Choose a trigger:", ["Comment", "DM", "Story Reply"]
    )

    # Trigger Word
    trigger_word = st.text_input("Trigger Word")

    # Response Type
    st.subheader("Response Type")
    response_type = st.radio("Choose response type:", ["Text Only", "Text + Button"])

    response_message = st.text_area("Response Message")

    buttons = []
    if response_type == "Text + Button":
        st.subheader("Add Buttons")
        for i in range(1, 3):
            btn_label = st.text_input(f"Button {i} Label", key=f"btn_label_{i}")
            btn_url = st.text_input(f"Button {i} URL", key=f"btn_url_{i}")
            if btn_label and btn_url:
                buttons.append({"label": btn_label, "url": btn_url})

    # Save Automation
    if st.button("Save Automation"):
        if not response_message:
            st.error("Response message is required.")
        elif trigger_type == "Comment" and not trigger_word:
            st.error("Trigger word is required for comments.")
        else:
            automation_data = {
                "trigger_type": trigger_type,
                "trigger_word": trigger_word,
                "response_type": response_type,
                "response_message": response_message,
                "buttons": buttons,
            }
            save_automation(automation_data)

# Handle Triggers and Responses
def handle_trigger(trigger_type, trigger_word, response_message, buttons):
    headers = {"Authorization": f"Bearer {st.session_state.access_token}"}

    # Example endpoint for handling comments
    if trigger_type == "Comment":
        url = f"{GRAPH_API_BASE}/{st.session_state.instagram_id}/media?fields=comments{{id,message}}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            comments = response.json().get("data", [])
            for comment in comments:
                if trigger_word.lower() in comment["message"].lower():
                    comment_id = comment["id"]
                    reply_url = f"{GRAPH_API_BASE}/{comment_id}/replies"
                    payload = {"message": response_message}

                    if buttons:
                        payload["attachment"] = {
                            "type": "template",
                            "payload": {
                                "template_type": "button",
                                "text": response_message,
                                "buttons": [
                                    {"type": "web_url", "url": btn["url"], "title": btn["label"]}
                                    for btn in buttons
                                ],
                            },
                        }

                    reply_response = requests.post(reply_url, headers=headers, json=payload)
                    if reply_response.status_code == 200:
                        st.success(f"Replied to comment: {comment['message']}")

# View Automations Section
def view_automations():
    st.title("View Automations")

    automation_list = list(automations.find())
    if not automation_list:
        st.info("No automations found.")
        return

    for automation in automation_list:
        st.write(f"**Trigger Type**: {automation['trigger_type']}")
        st.write(f"**Trigger Word**: {automation.get('trigger_word', '-')}")
        st.write(f"**Response Message**: {automation['response_message']}")

        if automation.get("buttons"):
            st.write("**Buttons:**")
            for btn in automation["buttons"]:
                st.write(f"- {btn['label']} ({btn['url']})")

        if st.button("Delete", key=str(automation["_id"])):
            automations.delete_one({"_id": ObjectId(automation["_id"])})
            st.experimental_rerun()

# Streamlit Navigation
menu = st.sidebar.selectbox("Menu", ["Login", "Create Automation", "View Automations"])
if menu == "Login":
    login()
elif menu == "Create Automation":
    create_automation()
elif menu == "View Automations":
    view_automations()
