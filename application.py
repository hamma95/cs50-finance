import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute(
        "SELECT symbol, company, SUM(shares) FROM transactions WHERE user_id= :user_id GROUP BY symbol HAVING SUM(shares) > 0",
        user_id=session.get('user_id'),
    )
    symbols = [row['symbol'] for row in rows]
    companies = [row['company'] for row in rows]
    shares = [int(row['SUM(shares)']) for row in rows]
    current_prices = [lookup(row['symbol'])['price'] for row in rows]
    stocks_values = [price * share for price, share in zip(current_prices, shares)]
    cash = db.execute("SELECT cash FROM users WHERE user_id = :user_id", user_id=session.get('user_id'))[0]['cash']
    cash = float(cash)

    return render_template(
        'index.html',
        values=zip(symbols, companies, shares, current_prices, stocks_values),
        cash=cash,
        total=cash+sum(stocks_values)
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol').upper()
        try:
            shares = int(request.form.get('shares'))
            if shares <= 0:
                return apology('shares must be a positive number')

        except ValueError:
            return apology('stop messing around and enter a valid number')

        if not symbol:
            return apology("missing symbol")
        if not shares:
            return apology("missing shares")
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol")
        balance = db.execute("SELECT cash FROM users WHERE user_id = :user_id", user_id=session.get('user_id'))[0]['cash']
        if balance < shares * quote['price']:
            return apology("Invalid symbol")
        db.execute(
            "INSERT INTO transactions (user_id, shares, symbol, company, price) VALUES(:user_id, :shares, :symbol,:company,:price)",
            user_id=int(session['user_id']),
            shares=shares,
            symbol=symbol,
            company=quote['name'],
            price=quote['price'],
        )
        db.execute(
            "UPDATE users SET cash = :cash WHERE user_id = :user_id",
            cash=balance - shares * quote.get('price'),
            user_id=session.get('user_id')
        )

        flash('Bought!')
        return redirect(url_for('index'))
    return render_template("buy.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id=session.get('user_id')
    if request.method == 'POST':
        symbol=request.form.get('symbol')
        try:
            sell_shares = int(request.form.get('shares'))
            if sell_shares <= 0:
                return apology("shares must be a positive number")
        except ValueError:
            return apology("Well yes, but actually no")


        owned_shares = db.execute(
        "SELECT SUM(shares) FROM transactions WHERE user_id= :user_id AND symbol = :symbol",
        symbol=symbol,
        user_id=user_id,
        )
        owned_shares = int(owned_shares[0]['SUM(shares)'])

        if sell_shares > owned_shares:
            return apology("Too many shares")

        quote = lookup(symbol)

        db.execute("UPDATE users SET cash = cash + :profit WHERE user_id = :user_id",
        profit=sell_shares*quote['price'],
        user_id=user_id,
        )
        db.execute(
            "INSERT INTO transactions (user_id, shares, symbol, company, price) VALUES(:user_id, :shares, :symbol,:company,:price)",
            user_id=user_id,
            shares=-sell_shares,
            symbol=symbol,
            company=quote['name'],
            price=quote['price'],
        )
        flash('SOLD!!')
        return redirect(url_for('index'))
    symbols = db.execute('SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0',
        user_id=user_id)
    return render_template("sell.html", symbols=symbols)


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get('username')
    usernames = db.execute('SELECT username FROM users WHERE username = :username', username=username)
    message = True if not usernames else False
    return jsonify(message)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute(
        'SELECT * FROM transactions WHERE user_id = :user_id',
        user_id=session.get('user_id')
    )

    return render_template('history.html', rows=rows)


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
        rows = db.execute("SELECT user_id, hash FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

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
    quote = {}
    status = 200
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        quote = lookup(symbol)
        if not symbol:
            flash('please enter a symbol')
            status = 400
        if symbol and not quote:
            flash('Invalid Symbol')
            status = 400
    return render_template("quote.html", quote=quote), status







@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        user = {}
        user['username'] = request.form.get('username')
        user['password'] = request.form.get('password')
        user['confirmation'] = request.form.get('confirmation')
        missing_required = not all(value for value in user.values())
        passwd_match = user['password'] == user['confirmation']
        if missing_required:
            return apology("Missing required field")
        if not passwd_match:
            return apology("Passwords do not match")

        user_id = db.execute(
            "INSERT INTO users (username, hash) VALUES (:username, :hashed)",
            username=user['username'],
            hashed=generate_password_hash(user['password']),
        )
        if not user_id:
            return apology('username taken')
        session['user_id'] = user_id
        return redirect(url_for("index"))
    return render_template("register.html")




def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
