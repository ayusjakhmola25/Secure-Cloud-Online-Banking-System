import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ayush123",
        database="securebank"
    )
    cursor = conn.cursor()
    for table in ["users", "accounts", "transactions"]:
        cursor.execute(f"SHOW CREATE TABLE {table}")
        print(f"--- {table} ---")
        print(cursor.fetchone()[1])
    cursor.close()
    conn.close()
except Exception as e:
    print(e)
