from fastapi import FastAPI, HTTPException, Depends, Security
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List

app = FastAPI()

class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int

# Simulación de base de datos de usuarios
class User(BaseModel):
    id: int
    username: str
    password: str
    email: str

class Customer(BaseModel):
    id: int
    name: str
    email: str
    address: str

customers_db = []

class CreditCard(BaseModel):
    card_number: str  # Número de tarjeta de crédito
    expiration_date: str  # Fecha de caducidad en formato MM/YY
    cvv: str  # Código de seguridad de la tarjeta

class Payment(BaseModel):
    id: int
    credit_card: CreditCard
    order_id: int # Cantidad de productos a comprar

payments_db = []

# Ejemplo de base de datos de inventario
inventory_db = {
    1: {"name": "Sweater", "stock": 14, "price": 50.0},
    # Otros productos aquí...
}

class OrderItem(BaseModel):
    product_id: int
    quantity: int

class Order(BaseModel):
    id: int
    customer_id: int
    items: List[OrderItem]

orders_db = []

# Simulación de base de datos de usuarios en memoria
users = [
    User(id=1, username="user1", password="password1", email="user1@example.com")
]

products_db = []

# Configuración de autenticación
SECRET_KEY = "mi_secreto_secreto"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Clase para autenticación y autorización
class AuthHandler:
    def authenticate_user(self, username: str, password: str):
        user = next((x for x in users if x.username == username), None)
        if not user or user.password != password:
            return False
        return user

    def create_access_token(self, data: dict, expires_delta: timedelta = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

auth_handler = AuthHandler()

# Ruta para la autenticación y generación de token JWT
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth_handler.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth_handler.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Ruta protegida que requiere autenticación
@app.get("/items/")
async def read_items(token: str = Security(oauth2_scheme)):
    return {"token": token}


auth_handler = AuthHandler()

# Ruta para la creación de un nuevo producto en el inventario
@app.post("/products/")
async def create_product(product: Product, token: str = Security(oauth2_scheme)):
    # Aquí deberías implementar la lógica para crear un nuevo producto en tu base de datos
    # Por ahora, solo estamos simulando la creación del producto
    products_db.append(product)
    return {"message": "Product created successfully"}

# Ruta para obtener todos los productos del inventario
@app.get("/products/")
async def get_all_products(token: str = Security(oauth2_scheme)):
    # Aquí deberías implementar la lógica para obtener todos los productos de tu base de datos
    # Por ahora, solo estamos simulando la obtención de los productos
    return products_db

# Ruta para obtener un producto específico por su ID
@app.get("/products/{product_id}")
async def get_product(product_id: int, token: str = Security(oauth2_scheme)):
    # Aquí deberías implementar la lógica para obtener un producto específico de tu base de datos por su ID
    # Por ahora, solo estamos simulando la obtención del producto
    product = next((product for product in products_db if product.id == product_id), None)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

# Ruta para actualizar un producto existente por su ID
@app.put("/products/{product_id}")
async def update_product(product_id: int, product: Product, token: str = Security(oauth2_scheme)):
    # Aquí deberías implementar la lógica para actualizar un producto existente en tu base de datos por su ID
    # Por ahora, solo estamos simulando la actualización del producto
    existing_product = next((p for p in products_db if p.id == product_id), None)
    if existing_product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    existing_product.name = product.name
    existing_product.description = product.description
    existing_product.price = product.price
    existing_product.quantity = product.quantity
    return {"message": "Product updated successfully"}

# Ruta para eliminar un producto existente por su ID
@app.delete("/products/{product_id}")
async def delete_product(product_id: int, token: str = Security(oauth2_scheme)):
    # Aquí deberías implementar la lógica para eliminar un producto existente en tu base de datos por su ID
    # Por ahora, solo estamos simulando la eliminación del producto
    global products_db
    products_db = [p for p in products_db if p.id != product_id]
    return {"message": "Product deleted successfully"}

@app.post("/customers/")
async def create_customer(customer: Customer, token: str = Security(oauth2_scheme)):
    customers_db.append(customer)
    return {"message": "Customer created successfully"}

@app.get("/customers/")
async def get_all_customers(token: str = Security(oauth2_scheme)):
    return customers_db

@app.get("/customers/{customer_id}")
async def get_customer(customer_id: int, token: str = Security(oauth2_scheme)):
    customer = next((customer for customer in customers_db if customer.id == customer_id), None)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

@app.put("/customers/{customer_id}")
async def update_customer(customer_id: int, customer: Customer, token: str = Security(oauth2_scheme)):
    existing_customer = next((c for c in customers_db if c.id == customer_id), None)
    if existing_customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    existing_customer.name = customer.name
    existing_customer.email = customer.email
    existing_customer.address = customer.address
    return {"message": "Customer updated successfully"}

@app.delete("/customers/{customer_id}")
async def delete_customer(customer_id: int, token: str = Security(oauth2_scheme)):
    global customers_db
    customers_db = [c for c in customers_db if c.id != customer_id]
    return {"message": "Customer deleted successfully"}

@app.post("/payments/")
async def create_payment(payment: Payment, token: str = Security(oauth2_scheme)):
    # Verificar si la orden asociada existe
    order_exists = any(order.id == payment.order_id for order in orders_db)
    if not order_exists:
        raise HTTPException(status_code=404, detail=f"Order with id {payment.order_id} not found")
    
    # Crear el pago
    payments_db.append(payment)
    return {"message": "Payment created successfully"}

@app.get("/payments/")
async def get_all_payments(token: str = Security(oauth2_scheme)):
    return payments_db

@app.get("/payments/{payment_id}")
async def get_payment(payment_id: int, token: str = Security(oauth2_scheme)):
    payment = next((payment for payment in payments_db if payment.id == payment_id), None)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment

@app.put("/payments/{payment_id}")
async def update_payment(payment_id: int, payment: Payment, token: str = Security(oauth2_scheme)):
    existing_payment = next((p for p in payments_db if p.id == payment_id), None)
    if existing_payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    existing_payment.credit_card = payment.credit_card
    existing_payment.order_id = payment.order_id
    return {"message": "Payment updated successfully"}

@app.delete("/payments/{payment_id}")
async def delete_payment(payment_id: int, token: str = Security(oauth2_scheme)):
    global payments_db
    payments_db = [p for p in payments_db if p.id != payment_id]
    return {"message": "Payment deleted successfully"}


@app.post("/orders/")
async def create_order(order: Order, token: str = Security(oauth2_scheme)):
    # Verificar si hay suficiente stock para los productos en la orden
    for item in order.items:
        product = inventory_db.get(item.product_id)
        if product is None:
            raise HTTPException(status_code=404, detail=f"Product with id {item.product_id} not found")
        if product["stock"] < item.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for product with id {item.product_id}")

    # Crear la orden
    orders_db.append(order)
    return {"message": "Order created successfully"}

@app.get("/orders/")
async def get_all_orders(token: str = Security(oauth2_scheme)):
    return orders_db

@app.get("/orders/{order_id}")
async def get_order(order_id: int, token: str = Security(oauth2_scheme)):
    order = next((order for order in orders_db if order.id == order_id), None)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.put("/orders/{order_id}")
async def update_order(order_id: int, order: Order, token: str = Security(oauth2_scheme)):
    existing_order = next((o for o in orders_db if o.id == order_id), None)
    if existing_order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    existing_order.customer_id = order.customer_id
    existing_order.items = order.items
    return {"message": "Order updated successfully"}

@app.delete("/orders/{order_id}")
async def delete_order(order_id: int, token: str = Security(oauth2_scheme)):
    global orders_db
    orders_db = [o for o in orders_db if o.id != order_id]
    return {"message": "Order deleted successfully"}