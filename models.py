from tortoise import fields
from tortoise.models import Model

class Product(Model):
    id = fields.IntField(pk=True)
    title = fields.CharField(max_length=255)
    price = fields.FloatField()
    description = fields.TextField()
    category = fields.CharField(max_length=100)
    image = fields.CharField(max_length=255)

class ProductIn(Model):
    title = fields.CharField(max_length=255)
    price = fields.FloatField()
    description = fields.TextField()
    category = fields.CharField(max_length=100)
    image = fields.CharField(max_length=255)

class Payment(Model):
    id = fields.IntField(pk=True)
    card_number = fields.CharField(max_length=16)
    cardholder_name = fields.CharField(max_length=255)
    expiration_date = fields.CharField(max_length=5)
    cvv = fields.CharField(max_length=3)

class Customer(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255)
    phone = fields.CharField(max_length=15)

class Order(Model):
    id = fields.IntField(pk=True)
    customer = fields.ForeignKeyField('models.Customer', related_name='orders')
    products = fields.ManyToManyField('models.Product', related_name='orders')
    payment = fields.ForeignKeyField('models.Payment', related_name='orders')
