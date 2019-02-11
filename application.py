#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Modularize code by using lots of functions and comments


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category)
    items = session.query(Item)
    return render_template('catalog.html', categories=categories, items=items)


@app.route('/catalog/<categoryName>/')
@app.route('/catalog/<categoryName>/items')
def showCategory(categoryName):
    categories = session.query(Category)
    category = categories.filter_by(name=categoryName).one()

    items = session.query(Item).filter_by(category_id=category.id)

    catName = category.name[0].upper() + category.name[1:]

    return render_template('items.html', categories=categories, catName=catName, items=items)


@app.route('/catalog/<categoryName>/<itemName>')
def showItem(categoryName, itemName):
    item = session.query(Item).filter_by(name=itemName).one()
    return render_template('item.html', item=item)


@app.route('/catalog/<categoryName>/new')
@app.route('/catalog/<categoryName>/items/new')
def newItem(categoryName):
    return render_template('new-item.html', categoryName=categoryName)


@app.route('/catalog/<categoryName>/<itemName>/edit')
def editItem(categoryName, itemName):
    return render_template('edit-item.html', categoryName=categoryName, itemName=itemName)


@app.route('/catalog/<categoryName>/<itemName>/delete')
def deleteItem(categoryName, itemName):
    return "Delete items here"


@app.route('/catalog.json')
def catalogJSON():
    return "The JSON goes here"


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
