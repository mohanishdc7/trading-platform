import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Create new table, and index (for efficient search later on) to keep track of stock orders, by each user
db.execute("CREATE TABLE IF NOT EXISTS ledger \
            (id INTEGER, userID NUMERIC NOT NULL, symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL, timestamp TEXT, \
            PRIMARY KEY(id), FOREIGN KEY(userID) REFERENCES users(id))")
db.execute("CREATE INDEX IF NOT EXISTS orders_by_user_id_index ON ledger (userID)")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query for getting user's portfolio of stocks
    stocks = db.execute(\
        "SELECT symbol, SUM(shares) as shares FROM ledger WHERE userID = ? GROUP BY symbol HAVING SUM(shares) > 0", session["user_id"])

    stock_cash = 0
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["shares"]
        stock_cash += stock["total"]

    # Query for user's cash balance
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    total_amount = stock_cash + user_cash[0]["cash"]

    return render_template("index.html", stocks=stocks, user_cash=user_cash[0]["cash"], total_amount=total_amount)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide symbol", 400)

        # Ensure shares submitted
        shares = request.form.get("shares")
        if not shares:
            return apology("Missing shares", 400)

         # Ensure shares submitted is an integer
        try:
            shares = int(shares)
            if shares < 1:
                return apology("Shares must be a positive integer", 400)
        except ValueError:
            return apology("Invalid shares", 400)

        # Ensure symbol exists
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid symbol", 400)

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        amount = shares * stock["price"]

        if amount > user_cash:
            return apology("Not enough cash", 400)

        # Update user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", amount, session["user_id"])

        # Add transaction into the ledger
        db.execute("INSERT INTO ledger (userID, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, ?)",\
                    session["user_id"], symbol.upper(), shares, stock["price"], datetime.now().strftime("%Y-%m-%d    %H:%M:%S"))

        flash("Transaction successful")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    stocks = db.execute("SELECT symbol FROM ledger WHERE userID = ? GROUP BY symbol", session["user_id"])
    return render_template("buy.html", stocks=stocks)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query database for transactions
    transactions = db.execute("SELECT * FROM ledger WHERE userID = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached via POST (as by submitting a form via method=post)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Ensure symbol exists
        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=quote["price"])

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached via POST (as by submitting a form via method=post)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not confirmation:
            return apology("must provide confirmation password", 400)

        # Ensure password and confirmation match
        elif confirmation != password:
            return apology("passwords don't match", 400)

        # Check if username already exists
        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        if len(rows) == 1:
            return apology("Username already taken", 400)

        # Query database for adding new registrant
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", \
                    username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

        flash("Registered!")

        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached via POST (as by submitting a form via method=post)
    if request.method == "POST":

        # Ensure symbol was submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide symbol", 400)

        # Ensure shares submitted
        shares = int(request.form.get("shares"))
        if not shares:
            return apology("Missing shares", 400)

        # Query for getting shares of a particular stock
        stock = db.execute("SELECT SUM(shares) as shares FROM ledger WHERE userID = ? AND symbol = ?", \
                            session["user_id"], symbol)[0]

        # Ensure stock exists in portfolio
        if stock is None:
            return apology("Invalid symbol", 400)

        # Ensure shares to be sold are less than available shares
        if shares > stock["shares"]:
            return apology("Too may shares", 400)

        price = lookup(symbol)["price"]
        amount = shares * price

        # Update user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id=?", amount, session["user_id"])

        # Add transaction to the ledger
        db.execute("INSERT INTO ledger (userID, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, ?)",\
                    session["user_id"], symbol.upper(), -shares, price, datetime.now().strftime("%Y-%m-%d    %H:%M:%S"))

        flash("Sold!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    stocks = db.execute("SELECT symbol FROM ledger WHERE userID = ? GROUP BY symbol", session["user_id"])
    return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
