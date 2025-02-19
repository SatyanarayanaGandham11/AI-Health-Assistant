import streamlit as st
import requests
import os

# Backend URL
API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

# Streamlit UI
st.set_page_config(page_title="AI Health Assistant", layout="wide")

st.title("🤖 AI Health Assistant Chatbot")
st.write("Your AI-powered assistant for health and wellness queries!")

# User Authentication
if "token" not in st.session_state:
    st.session_state.token = None

menu = st.sidebar.radio("Navigation", ["Chat", "Login", "Register", "Chat History"])

# Register User
if menu == "Register":
    st.subheader("Create an Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        response = requests.post(f"{API_URL}/auth/register", json={"username": username, "password": password})
        st.success(response.json().get("message", "Registration successful"))

# Login User
elif menu == "Login":
    st.subheader("Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        response = requests.post(f"{API_URL}/auth/login", json={"username": username, "password": password})
        if response.status_code == 200:
            st.session_state.token = response.json()["token"]
            st.success("Login successful!")
        else:
            st.error("Invalid username or password")

# Chat Interface
elif menu == "Chat":
    st.subheader("💬 Chat with AI Health Assistant")
    if st.session_state.token:
        query = st.text_input("Ask a health-related question:")
        if st.button("Submit"):
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            response = requests.post(f"{API_URL}/healthbot", headers=headers, json={"query": query})
            if response.status_code == 200:
                result = response.json()
                st.write("**Classification:**", result["classification"])
                st.write("**Response:**", result["response"])
            else:
                st.error("Failed to get response")
    else:
        st.warning("Please log in to chat with the AI assistant.")

# View Chat History
elif menu == "Chat History":
    st.subheader("📜 View Your Chat History")
    if st.session_state.token:
        headers = {"Authorization": f"Bearer {st.session_state.token}"}
        response = requests.get(f"{API_URL}/chat_history/", headers=headers)
        if response.status_code == 200:
            history = response.json()["history"]
            for date, chats in history.items():
                st.write(f"📅 **Date:** {date}")
                for chat in chats:
                    st.write(f"🔹 **Q:** {chat['query']}")
                    st.write(f"💡 **A:** {chat['response']}")
                    st.write("---")
        else:
            st.error("Failed to retrieve chat history")
    else:
        st.warning("Please log in to view your chat history.")

# Run Streamlit
if __name__ == "__main__":
    st.run()
