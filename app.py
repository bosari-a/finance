import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd


@app.template_filter("datetime_format")
def datetime_format(date_str) -> str:
    '''custom filter that formats date time into dd/mm/yy 12-hour clock time'''
    d_ = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
    return d_.strftime("%d/%m/%Y %I:%M %p")


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # get current cash value from user
    id = session['user_id']
    cash = db.execute("select cash from users where id = ?",
                      id)[0]["cash"]
    total = cash

    # get purchases of logged in user
    purchases = db.execute(
        "select symbol,price,sum(shares) as shares,name from purchases where user_id = ? group by symbol having sum(shares) > 0 order by transaction_date DESC;", id)

    # calculate actual total if user had purchased in the past
    if len(purchases):
        total = 0
        for purchase in purchases:
            total += purchase['price'] * purchase['shares']
        total += cash
    return render_template("index.html", cash=usd(cash), total=usd(total), purchases=purchases)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # lookup symbol data (call it q like query)
        q = lookup(symbol=symbol)

        # handle invalid symbols
        if not q:
            return apology("Invalid symbol")
        symbol = q.get("symbol")

        # else continue and get shares from form data
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")

        # handle 0 or negative shares input
        if shares <= 0:
            return apology("invalid amount of shares")

        # on valid symbol and valid shares quantity:
        id = session['user_id']

        # get the current cash of user from db
        cash = db.execute("SELECT cash FROM users WHERE id = ?",
                          session['user_id'])[0]['cash']

        # get price from lookup
        price = q.get("price")

        # update user cash in db
        cash -= shares * round(price, 2)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, id)

        # insert transaction into purchases table
        name = q.get('name')
        db.execute("INSERT INTO purchases (user_id, symbol, price, shares, name) VALUES (?, ?, ?, ?, ?)",
                   id, symbol, price, shares, name)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session['user_id']
    purchases = db.execute(
        "select symbol,shares,price,datetime(transaction_date, 'localtime') as transaction_date from purchases where user_id = ? order by transaction_date DESC", id)

    return render_template("history.html", purchases=purchases)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

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

    if request.method == "POST":
        symbol = request.form.get("symbol")

        # q is quote you get after looking up symbol
        q = lookup(symbol=symbol)

        # if no quote
        if not q:
            return apology("Invalid symbol")

        # else send info over to quoted page and redirect user there
        name = q.get("name")
        price = q.get("price")
        actual_symbol = q.get("symbol")
        return render_template("quoted.html", title=f"{name} quoted", name=name, price=usd(price), symbol=actual_symbol)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # forget any user_id
    session.clear()
    # POST request
    if request.method == "POST":

        username = request.form.get("username").strip()
        # validate username: apology if username is blank or already exists
        if not username:
            return apology("Can't simply have no username")
        username_check = db.execute(
            "select * from users where username = ?", username)
        if len(username_check) != 0:
            return apology(f"Sorry but {username} is already taken!")

        # on success validate password next
        elif len(username_check) == 0:
            password = request.form.get("password")
            confirm = request.form.get("confirmation")

            # if password or confirm fields are empty
            if not password.strip() or not confirm.strip():
                return apology("Password or confirm fields are empty")
            # if password is not re-entered correctly redirect
            if password != confirm:
                return apology("Sorry, your passwords don't seem to match")

            # on validated username and password insert user and set cookie
            pswd_hash = generate_password_hash(password=password)
            id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                            username, pswd_hash)
            session['user_id'] = id
            return redirect("/")
    # check session on GET register
    if session.get("user_id"):
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    id = session['user_id']

    if request.method == "POST":

        # get symbol from form data
        symbol = request.form.get("symbol")

        # if no symbol selected
        if not symbol:
            return apology("Invalid Symbol")

        # else continue and check shares
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")

        # shares less than or equal to zero are invalid
        if shares <= 0:
            return apology("Invalid shares")

        # else lookup the symbol
        q = lookup(symbol=symbol)

        # just for safety, if it is invalid return error page
        if not q:
            return apology("Invalid symbol")
        symbol = q.get("symbol")

        # else check request shares vs. user owned shares of corresponding symbol
        owned_shares = db.execute(
            "SELECT SUM(shares) as shares FROM purchases WHERE user_id = ? AND symbol = ?", id, symbol)[0]['shares']

        # case 1 if shares to sell less than or equal to owned shares then sale is valid
        # todo: insert purchase (negative shares) into purchases db
        # todo: update users cash with sold shares
        if shares <= owned_shares:
            price = round(q.get("price"), 2)
            name = q.get("name")
            db.execute("INSERT INTO purchases (user_id, symbol, price, shares, name) VALUES (?, ?, ?, ?, ?);",
                       id, symbol, price, shares*-1, name)
            cash = db.execute("SELECT cash from users where id = ?", id)[
                0]['cash']
            cash += shares * price
            db.execute("update users set cash = ? where id = ?", cash, id)
            return redirect("/")
        else:
            return apology("Invalid shares")

    # get symbols and pass them into sell template as options var
    symbols = db.execute(
        "SELECT symbol FROM purchases WHERE user_id = ? group by symbol", id)
    return render_template("sell.html", symbols=symbols)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    '''Change user password'''
    id = session['user_id']
    # if post request
    if request.method == "POST":
        current = request.form.get("current")
        new = request.form.get("new").strip()
        confirm = request.form.get("confirmation").strip()

        # validate current password
        actual_hash = db.execute(
            "select hash from users where id = ?", id)[0]['hash']
        if not check_password_hash(pwhash=actual_hash, password=current):
            return apology("Wrong password, not authorized to change password")

        # check if either input is empty
        if not new or not confirm:
            return apology("Invalid input")

        # else check if confirmation is same as password
        if confirm != new:
            return apology("Sorry, password and confirmation don't match")

        # if all is valid update user's password with the new one
        new_hash = generate_password_hash(new)
        db.execute("update users set hash = ? where id = ?", new_hash, id)
        return redirect("/")

    # else render the page on GET requests
    return render_template("change_pswd.html")
