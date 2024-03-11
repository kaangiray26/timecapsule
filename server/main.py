#! env/bin/python
#-*- coding: utf-8 -*-

import os
import json
import hashlib
import secrets
import time
import base64
from datetime import datetime
import argparse
import asyncio

# Server details
port = 9000
address = "localhost"

# Socket connections
connections = set()

async def message_handler(websocket, data):
    match data['type']:
        case 'encrypt':
            pass

async def handle(websocket):
    # Add new connection
    connections.add(websocket)
    
    # Send queue to the new client
    data = {
        "type": "hash",
        "hash": None
    }
    await websocket.send(json.dumps(data))
    
    # Handle incoming messages
    async for message in websocket:
        print(f"Received: {message}")
        data = json.loads(message)
        await message_handler(websocket, data)
        
    # Remove the connection
    try:
        await websocket.wait_closed()
    finally:
        connections.remove(websocket)

async def main():
    async with websockets.serve(handle, address, port):
        await broadcast_queue()

if __name__ == "__main__":
    print(f"Server started on ws://{address}:{port}")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping server...")