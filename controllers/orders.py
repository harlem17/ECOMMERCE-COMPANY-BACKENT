# controllers/orders.py

from fastapi import APIRouter, HTTPException
from models import Order, CustomerIn, PaymentIn
from typing import List

router = APIRouter()

@router.post("/orders/")
async def create_order(payment: PaymentIn, customer: CustomerIn, product_id: int):
    try:
        new_customer = await Customer.create(**customer.dict())
        payment_obj = await Payment.create(**payment.dict())
        product = await Product.get_or_none(id=product_id)
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")
        order = await Order.create(customer=new_customer, payment=payment_obj)
        await order.products.add(product)
        return order
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while creating the order")

@router.get("/orders/", response_model=List[Order])
async def get_all_orders() -> List[Order]:
    orders = await Order.all()
    return orders

@router.get("/orders/{order_id}", response_model=Order)
async def get_order(order_id: int):
    order = await Order.get_or_none(id=order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@router.delete("/orders/{order_id}")
async def delete_order(order_id: int):
    order = await Order.get_or_none(id=order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    await order.delete()
    return {"message": "Order deleted successfully"}
