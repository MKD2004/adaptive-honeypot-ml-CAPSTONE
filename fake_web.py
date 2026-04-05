# fake_web.py
from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Honeypot hit successful"

app.run(port=8081)