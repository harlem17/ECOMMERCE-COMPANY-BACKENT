# controllers/customers.py

from fastapi import APIRouter, HTTPException
from models import Customer, CustomerIn
from typing import List

router = APIRouter()

@router.post("/customers/")
async def create_customer(customer: CustomerIn):
    customer_obj = await Customer.create(**customer.dict())
    return customer_obj

@router.get("/customers/", response_model=List[Customer])
async def get_all_customers() -> List[Customer]:
    customers = await Customer.all()
    return customers

@router.get("/customers/{customer_id}", response_model=Customer)
async def get_customer(customer_id: int):
    customer = await Customer.get_or_none(id=customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

@router.put("/customers/{customer_id}", response_model=Customer)
async def update_customer(customer_id: int, customer: CustomerIn):
    existing_customer = await Customer.get_or_none(id=customer_id)
    if existing_customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    await existing_customer.update_from_dict(customer.dict()).save()
    return existing_customer

@router.delete("/customers/{customer_id}")
async def delete_customer(customer_id: int):
    customer = await Customer.get_or_none(id=customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    await customer.delete()
    return {"message": "Customer deleted successfully"}
