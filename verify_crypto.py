import requests
import re
import mysql.connector

URL = "http://127.0.0.1:5000"

def test():
    session = requests.Session()
    res = session.get(f"{URL}/auth/register")
    match = re.search(r'name="csrf_token" value="(.*?)"', res.text)
    if not match:
        print("CSRF Token not found!")
        return
    csrf = match.group(1)
    
    res = session.post(f"{URL}/auth/register", data={
        "csrf_token": csrf,
        "full_name": "Test User",
        "email": "testcrypto3@example.com",
        "phone": "3334445555",
        "password": "securepassword123"
    })
    
    # Login
    res = session.get(f"{URL}/auth/login")
    match = re.search(r'name="csrf_token" value="(.*?)"', res.text)
    if not match:
        return
    csrf = match.group(1)
    
    res = session.post(f"{URL}/auth/login", data={
        "csrf_token": csrf,
        "email": "testcrypto3@example.com",
        "password": "securepassword123"
    })
    
    # Verify DB
    conn = mysql.connector.connect(host="localhost", user="root", password="ayush123", database="securebank")
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email='testcrypto3@example.com'")
    user = cur.fetchone()
    if user:
        if isinstance(user["password_hash"], str):
            p_hash = user["password_hash"].encode('utf-8')
        else:
            p_hash = user["password_hash"]
            
        print("User DB Entry Success")
        print("User.password_hash starts with $2: ", p_hash.startswith(b'$2'))
        print("User.phone encrypted: ", len(user["phone"]) > 30)
        
        cur.execute("SELECT * FROM accounts WHERE user_id=%s", (user["user_id"],))
        account = cur.fetchone()
        print("Account DB Entry Success")
        print("Account.account_number encrypted: ", len(account["account_number"]) > 20)
    else:
        print("Failed to register/find user in DB.")
        
    conn.close()

if __name__ == '__main__':
    test()
