import sqlite3
import json
import os
from datetime import datetime
from telethon.sync import TelegramClient
import secrets

API_ID = os.environ["TELEGRAM_API_ID"]
API_HASH = os.environ["TELEGRAM_API_HASH"]
PHONE_NUMBER = os.environ["TELEGRAM_PHONE_NUMBER"]
DB_PATH = "/var/csirt/source/scanner/db.sqlite3"

CHANNEL_LINKS = [
    'https://t.me/noname05716',
    'https://t.me/+fiTz615tQ6BhZWFi',
    'https://t.me/killnetl'
]

def load_last_message_ids():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT channel_link, last_message_id FROM nessus_telegramdataids")
    ids = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return ids

def save_last_message_id(channel_link, last_message_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO nessus_telegramdataids (channel_link, last_message_id) VALUES (?, ?)", (channel_link, last_message_id))
    conn.commit()
    conn.close()

def count_existing_messages(channel_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM nessus_telegramdata WHERE channel=?", (channel_name,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def fetch_messages_from_channels(client):
    last_message_ids = load_last_message_ids()

    for channel_link in CHANNEL_LINKS:
        try:
            channel = client.get_entity(channel_link)
            
            min_id = last_message_ids.get(channel_link, 0)
            existing_messages_count = count_existing_messages(channel.title)
            
            messages = client.get_messages(channel, limit=None, min_id=min_id)
            
            insert_messages_into_db(messages, channel.title)
            
            new_messages_count = count_existing_messages(channel.title) - existing_messages_count
            
            print(f"Total messages fetched from {channel_link}: {len(messages)}")
            print(f"New messages added to the database: {new_messages_count}")

            if messages:
                # Save the highest message ID for the next iteration.
                max_id = max([msg.id for msg in messages])
                save_last_message_id(channel_link, max_id)
        
        except Exception as e:
            print(f"Error processing channel {channel_link}: {e}")

def insert_messages_into_db(messages, channel_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for message in reversed(messages):
        #... [rest of the code remains unchanged]

if __name__ == "__main__":
    with TelegramClient('anon', API_ID, API_HASH) as client:
        fetch_messages_from_channels(client)
