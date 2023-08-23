#!/usr/bin/env python
# pip install websockets
# zypper in python3-websockets

import asyncio
from websockets.server import serve

async def echo(websocket, path):
    print("got request from:", path)
    async for message in websocket:
        await websocket.send(message)

async def main():
    async with serve(echo, "localhost", 8765):
        await loop.create_future()


loop = asyncio.get_event_loop()
task = loop.create_task(main())
loop.run_until_complete(task)
