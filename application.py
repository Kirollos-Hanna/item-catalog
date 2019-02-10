#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)

engine = create_engine('sqlite:///catalogappdatabase.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Modularize code by using lots of functions and comments


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category)
    return render_template('catalog.html', categories=categories)


@app.route('/catalog/<categoryName>/')
@app.route('/catalog/<categoryName>/items')
def showCategory(categoryName):
    return "This is the catalog for {}".format(categoryName)


@app.route('/catalog/<categoryName>/<itemName>')
def showItem(categoryName, itemName):
    return "This is {} in {}".format(itemName, categoryName)


@app.route('/catalog/<categoryName>/new')
@app.route('/catalog/<categoryName>/items/new')
def newItem(categoryName):
    return "Create a new item here"


@app.route('/catalog/<categoryName>/<itemName>/edit')
def editItem(categoryName, itemName):
    return "Edit items here"


@app.route('/catalog/<categoryName>/<itemName>/delete')
def deleteItem(categoryName, itemName):
    return "Delete items here"


@app.route('/catalog.json')
def catalogJSON():
    return "The JSON goes here"


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
