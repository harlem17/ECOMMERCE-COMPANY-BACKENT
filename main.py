from fastapi import FastAPI, HTTPException
from tortoise.contrib.fastapi import register_tortoise
from models import Product, Payment, Customer, Order
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.hash import bcrypt

app = FastAPI()

# Definición de los modelos
class ProductIn(BaseModel):
    title: str
    price: float
    description: str
    category: str
    image: str

class PaymentIn(BaseModel):
    card_number: str
    cardholder_name: str
    expiration_date: str
    cvv: str

class CustomerIn(BaseModel):
    name: str
    email: str
    phone: str

class OrderUpdate(BaseModel):
    customer_id: int
    payment_id: int
    product_ids: List[int]

# Configuración de seguridad
SECRET_KEY = "TuSuperClaveSecreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simulación de una base de datos de usuarios
fake_users_db = {
    "user1": {
        "username": "user1",
        "hashed_password": bcrypt.hash("password1")  # Aquí debería ir el hash de la contraseña "password1"
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Clase para manejar la autenticación
class AuthHandler:
    def __init__(self, secret_key: str, algorithm: str, access_token_expire_minutes: int):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def decode_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None

auth_handler = AuthHandler(SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES)

def verify_token(token: str) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return True
    except JWTError:
        return False

# Ruta para autenticar usuarios y obtener un token de acceso
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not auth_handler.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth_handler.create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Ruta protegida que requiere un token de acceso
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    payload = auth_handler.decode_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return {"username": username}

# Registro de tortoise
register_tortoise(
    app,
    db_url="postgres://postgres:ozfxkfOxRgkmOnNUkrnpPLrSakQOQsbg@monorail.proxy.rlwy.net:49881/railway",
    modules={"models": ["models"]},
    generate_schemas=True
)

@app.post("/products/")
async def create_product(product: ProductIn, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    product_obj = await Product.create(**product.dict())
    return product_obj

@app.get("/products/", response_model=List[dict])
async def get_all_products(token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    products = await Product.all().values()
    return products

@app.put("/products/{product_id}")
async def update_product(product_id: int, product: ProductIn, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Verificar si el producto existe
    existing_product = await Product.get_or_none(id=product_id)
    if existing_product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

    # Actualizar el producto con los nuevos datos
    await existing_product.update_from_dict(product.dict()).save()

    # Devolver el producto actualizado
    return existing_product

@app.delete("/products/{product_id}")
async def delete_product(product_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener el producto
    product = await Product.get_or_none(id=product_id)

    # Si el producto no existe, devuelve un error 404
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

    # Si el producto existe, elimínalo de la base de datos
    await product.delete()

    return {"message": "Product deleted successfully"}

# Ruta para obtener todos los pagos
@app.get("/payments/", response_model=List[dict])
async def get_all_payments(token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Si el token es válido, obtener todos los pagos
    payments = await Payment.all().values()
    return payments

# Ruta para procesar un pago
@app.post("/payments/")
async def process_payment(payment: PaymentIn, customer: CustomerIn, product_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        # Crear el cliente
        new_customer = await Customer.create(**customer.dict())

        # Crear el pago
        payment_obj = await Payment.create(**payment.dict())

        # Crear la orden
        product = await Product.get_or_none(id=product_id)
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")

        order = await Order.create(customer=new_customer, payment=payment_obj)
        await order.products.add(product)

        return JSONResponse(content={"message": "Payment processed successfully", "order_id": order.id})
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while processing the payment")

# Ruta para actualizar un pago por su ID
@app.put("/payments/{payment_id}/")
async def update_payment(payment_id: int, payment_update: PaymentIn, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener el pago existente
    existing_payment = await Payment.get_or_none(id=payment_id)
    
    # Si el pago no existe, devuelve un error 404
    if existing_payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    # Si el pago existe, actualízalo con los datos proporcionados
    await existing_payment.update_from_dict(payment_update.dict()).save()
    
    return existing_payment

# Ruta para eliminar un pago por su ID
@app.delete("/payments/{payment_id}")
async def delete_payment(payment_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener el pago
    payment = await Payment.get_or_none(id=payment_id)
    
    # Si el pago no existe, devuelve un error 404
    if payment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment not found")
    
    # Si el pago existe, elimínalo de la base de datos
    await payment.delete()
    
    return {"message": "Payment deleted successfully"}

# Ruta para obtener todos los clientes
@app.get("/customers/", response_model=List[dict])
async def get_all_customers(token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Si el token es válido, obtener todos los clientes
    customers = await Customer.all().values()
    return customers

# Ruta para crear un nuevo cliente
@app.post("/customers/", response_model=dict)  
async def create_customer(customer: CustomerIn, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Crear el cliente con los datos proporcionados
    customer_obj = await Customer.create(**customer.dict())
    return customer_obj.dict()

# Ruta para actualizar un cliente por su ID
@app.put("/customers/{customer_id}")
async def update_customer(customer_id: int, customer: CustomerIn, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener el cliente existente
    existing_customer = await Customer.get_or_none(id=customer_id)
    if existing_customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    # Actualizar los datos del cliente con los nuevos datos
    await existing_customer.update_from_dict(customer.dict()).save()
    
    # Devolver el cliente actualizado
    return existing_customer

# Ruta para eliminar un cliente por su ID
@app.delete("/customers/{customer_id}/")
async def delete_customer(customer_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener el cliente
    customer = await Customer.get_or_none(id=customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    # Si el cliente existe, elimínalo de la base de datos
    await customer.delete()
    
    return {"message": "Customer deleted successfully"}

# Ruta para obtener todas las órdenes
@app.get("/orders/", response_model=List[dict])
async def get_all_orders(token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Si el token es válido, obtener todas las órdenes
    orders = await Order.all().values()
    return orders

# Ruta para crear una nueva orden
@app.post("/orders/", response_model=dict)
async def create_order(payment: PaymentIn, customer: CustomerIn, product_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        # Crear el cliente si no existe
        customer_obj = await Customer.get_or_create(**customer.dict())

        # Crear el pago
        payment_obj = await Payment.create(**payment.dict())

        # Obtener el producto
        product = await Product.get_or_none(id=product_id)
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")

        # Crear la orden y agregar el producto
        order = await Order.create(customer=customer_obj, payment=payment_obj)
        await order.products.add(product)

        return {"message": "Order created successfully", "order_id": order.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while creating the order")

# Ruta para actualizar una orden por su ID
@app.put("/orders/{order_id}")
async def update_order(order_id: int, order_update: OrderUpdate, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Verificar si la orden existe
    existing_order = await Order.get_or_none(id=order_id)
    if existing_order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # Actualizar los datos de la orden con los nuevos datos proporcionados
    if order_update.customer_id is not None:
        existing_order.customer_id = order_update.customer_id
    if order_update.payment_id is not None:
        existing_order.payment_id = order_update.payment_id
    if order_update.product_ids is not None:
        existing_order.products.clear()
        for product_id in order_update.product_ids:
            product = await Product.get_or_none(id=product_id)
            if product:
                existing_order.products.add(product)

    # Guardar los cambios
    await existing_order.save()

    # Devolver la orden actualizada
    return existing_order

# Ruta para eliminar una orden por su ID
@app.delete("/orders/{order_id}/")
async def delete_order(order_id: int, token: str = Depends(oauth2_scheme)):
    # Verificar el token de acceso
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Intenta obtener la orden
    order = await Order.get_or_none(id=order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # Si la orden existe, elimínala de la base de datos
    await order.delete()

    return {"message": "Order deleted successfully"}

