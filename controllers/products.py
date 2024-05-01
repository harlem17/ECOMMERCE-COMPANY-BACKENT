from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

# Modelo Product
class Product(BaseModel):
    title: str
    price: float
    description: str
    category: str
    image: str

# Rutas de productos
@router.get("/products/{product_id}")
async def get_product(product_id: int):
    # Lógica para obtener un producto por su ID
    return {"product_id": product_id, "title": "Product Title", "price": 10.99, "description": "Product Description", "category": "Product Category", "image": "Product Image URL"}

@router.post("/products/")
async def create_product(product: Product):
    # Lógica para crear un nuevo producto
    return product

@router.put("/products/{product_id}")
async def update_product(product_id: int, product: Product):
    # Lógica para actualizar un producto existente
    return {"product_id": product_id, **product.dict()}

@router.delete("/products/{product_id}")
async def delete_product(product_id: int):
    # Lógica para eliminar un producto por su ID
    return {"message": f"Product with ID {product_id} has been deleted"}

# Otras operaciones CRUD para productos...
