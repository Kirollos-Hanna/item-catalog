# Description

The program uses Python, Flask and SQLAlchemy to retrieve data from a database and show it to the user. The user can see all availabe items and can login to make his/her own items as well as delete and edit those items but he/she can't delete or edit other users' items.

## Requirements

- Python 3: [Download the latest version of Python here](https://www.python.org/downloads/)
- SQLite: [Download from here](https://www.sqlite.org/download.html)
- SQLAlchemy: [Download from here](https://www.sqlalchemy.org/download.html)
- if you're on windows, download [git bash](https://git-scm.com/downloads)

## How to run

- Use git to clone this directory (https://github.com/Kirollos-Hanna/item-catalog)
- `cd` into the project directory.
- use the `python` or `python3` command with the application.py file from your command line. (i.e. `python application.py`)
- The server will run on port 5000 by default on your local machine. (Use localhost:5000 to view the website)

## How it works

- The user can login using the login page using a Google or Facebook account.
- Items can only be added to categories by a logged-in user.
- The user can only modify or delete his/her current items.
