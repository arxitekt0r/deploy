#!/bin/bash

# Install dependencies (if not already installed by Render)
pip install -r requirements.txt

# Run the FastAPI app with uvicorn
uvicorn main:app --host 0.0.0.0 --port 10000
