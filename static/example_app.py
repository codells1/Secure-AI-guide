import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "abc123secret"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'")
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


if __name__ == "__main__":
    app.run(debug=True)
