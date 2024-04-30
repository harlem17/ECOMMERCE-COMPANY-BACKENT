import psycopg2

try:
    connection = psycopg2.connect(
        database='ecommerce' ,
        user='postgres' ,
        host='localhost' ,
        password='kalethabh',
        port='5432'
        )

    print("Connection established")
except:
    print("Connection failed")
