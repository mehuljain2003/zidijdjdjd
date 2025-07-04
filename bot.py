from telethon import TelegramClient, events

# Replace with your actual values from my.telegram.org
api_id = 1234567
api_hash = 'your_api_hash_here'
bot_token = '7968614560:AAFXl7Bcm2aqqoVY2pHov8H1WEsYBC2F0bU'

bot = TelegramClient('bot', api_id, api_hash).start(bot_token=bot_token)

@bot.on(events.NewMessage(pattern='/start'))
async def start(event):
    await event.respond("🤖 Bot is up and running! Send /run to execute the script.")

@bot.on(events.NewMessage(pattern='/run'))
async def run_script(event):
    try:
        await event.respond("✅ Script logic triggered.")
    except Exception as e:
        await event.respond(f"❌ Error: {str(e)}")

print("Bot is running...")
bot.run_until_disconnected()