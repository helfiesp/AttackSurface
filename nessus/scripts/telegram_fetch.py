import asyncio
import sqlite3
import json
import os
from datetime import datetime
import secrets
from telethon.sync import TelegramClient

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

async def fetch_messages_from_channels():
    last_message_ids = load_last_message_ids()

    async with TelegramClient('anon', API_ID, API_HASH) as client:
        for channel_link in CHANNEL_LINKS:
            channel = await client.get_entity(channel_link)
            offset_id = last_message_ids.get(channel_link, 0)
            existing_messages_count = count_existing_messages(channel.title)

            messages = await client.get_messages(channel, limit=None, offset_id=offset_id)

            insert_messages_into_db(messages, channel.title)
            new_messages_count = count_existing_messages(channel.title) - existing_messages_count

            print(f"Total messages fetched from {channel_link}: {len(messages)}")
            print(f"New messages added to the database: {new_messages_count}")

            if messages:
                save_last_message_id(channel_link, messages[0].id)

def insert_messages_into_db(messages, channel_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for message in reversed(messages):
        data = {
            "Sender ID": message.sender_id,
            "Username": getattr(message.sender, 'username', 'N/A'),
            "Date": str(message.date),
            "Message ID": message.id,
            "Views": getattr(message, 'views', 'N/A'),
            "Replying to Message ID": getattr(message, 'reply_to_msg_id', 'N/A'),
            "Forwarded from ID": getattr(message.forward, 'sender_id', 'N/A') if message.forward else 'N/A',
            "Forwarded Date": str(getattr(message.forward, 'date', 'N/A')) if message.forward else 'N/A',
        }
        cursor.execute("""
            INSERT INTO nessus_telegramdata (channel, message, message_data, message_id, message_date, date_added)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (channel_name, message.text, json.dumps(data), message.id, str(message.date), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    conn.commit()
    conn.close()

asyncio.run(fetch_messages_from_channels())
