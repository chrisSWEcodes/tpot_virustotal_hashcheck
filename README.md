# TPOT VirusTotal hashcheck

The script will check the md5 hashsum from harvested malware in the Deutsche Telekom TPOT and notify you via telegram and also upload it if it's not found there.

It will also log some aspects, check inside compressed files and not bother the VT api twice for the same hash.

Sign up for a free account and API key here:
https://www.virustotal.com/

Get the awesome T-POT from here:
https://github.com/telekom-security/tpotce

Steps to Set Up Telegram Bot Notifications
Open Telegram and search for the BotFather.
Start a chat with BotFather and send the command /newbot.
Follow the instructions to create your bot and get the bot token.
Get Your Chat ID:
Open a chat with your bot in Telegram and send any message.
Visit the URL https://api.telegram.org/bot<your_bot_token>/getUpdates (replace <your_bot_token> with your actual token).
Look for the chat object in the response JSON and note the id (this is your chat_id).
Update the config file.

If you'd like the script to execute at a regular interval, use crontab -e as the user for tpot and input, for example:
cd /home/tpotuser/checkhash && /usr/bin/python3 /home/tpotuser/checkhash/checkhash.py
To have it executed every three hours.

Disclaimer:
The script is provided as-is and may be full of holes. Although, probably not. Maybe just sharks.

Happy fishing!
