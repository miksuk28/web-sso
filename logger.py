import aiofiles
import asyncio
from datetime import datetime

services = {
    0: "DEBUG",
    1: "AUTH",
    2: "FILESHARE",
    3: "NOTES",
    4: "IT-NET"
}

class Logger:
    def __init__(self, log_file):
        self._log_file = log_file

    async def _log(self, text, service_id, user=None, ip=None):
        async with aiofiles.open(self._log_file, mode="w") as f:
            await f.writelines(f"{services[service_id]} - {user} - {text} - {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")

    
    def log(self, text, service_id, user=None, ip=None):
        asyncio.run(self._log(text, service_id, user, ip))