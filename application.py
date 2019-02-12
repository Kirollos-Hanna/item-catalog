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
    itemsList = [item for item in items]
    # catName = category.name[0].upper() + category.name[1:]

    return render_template('items.html', categories=categories, categoryName=categoryName, items=itemsList, itemsLength=len(itemsList))


@app.route('/catalog/<categoryName>/<itemName>')
def showItem(categoryName, itemName):
    item = session.query(Item).filter_by(name=itemName).one()
    return render_template('item.html', item=item)


@app.route('/catalog/<categoryName>/new', methods=['GET', 'POST'])
@app.route('/catalog/<categoryName>/items/new', methods=['GET', 'POST'])
def newItem(categoryName):
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        newItem = Item(name=request.form['name'],
                       description=request.form['desc'],
                       category_id=category.id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showCategory', categoryName=categoryName))
    else:
        return render_template('new-item.html', categoryName=categoryName)


@app.route('/catalog/<categoryName>/<itemName>/edit', methods=['GET', 'POST'])
def editItem(categoryName, itemName):
    item = session.query(Item).filter_by(name=itemName).one()
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        item.name = request.form['name']
        item.description = request.form['desc']
        item.category_id = category.id
        session.add(item)
        session.commit()
        return redirect(url_for('showItem', categoryName=category.name, itemName=item.name))
    else:
        return render_template('edit-item.html', categoryName=categoryName, itemName=itemName)


@app.route('/catalog/<categoryName>/<itemName>/delete', methods=['GET', 'POST'])
def deleteItem(categoryName, itemName):
    if request.method == 'POST':
        item = session.query(Item).filter_by(name=itemName).one()
        session.delete(item)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-item.html', categoryName=categoryName, itemName=itemName)


@app.route('/catalog.json')
def catalogJSON():
    categories = session.query(Category)
    items = session.query(Item)

    categoriesJSON = [category.serialize for category in categories]
    itemsJSON = [item.serialize for item in items]

    return jsonify(Category=categoriesJSON, Items=itemsJSON)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
