import psycopg2
import os

# Configuración (Coincide con tus defaults del docker-compose)
DB_HOST = "localhost"
DB_NAME = "securecomm"
DB_USER = "securecomm"
DB_PASS = "securecomm"
DB_PORT = "5432"

def listar_registros(tabla):
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT
        )
        cur = conn.cursor()

        query = f"SELECT * FROM {tabla};"
        cur.execute(query)
        rows = cur.fetchall()

        print(f"--- Registros en '{tabla}' ---")
        for row in rows:
            print(row)

        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

# Cambia 'users' por el nombre real de tu tabla
if __name__ == "__main__":
    tabla_a_buscar = input("Introduce el nombre de la tabla: ")
    listar_registros(tabla_a_buscar)