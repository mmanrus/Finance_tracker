import os
import html
from cs50 import SQL # type: ignore
from flask import Flask, flash, redirect, render_template, request, session, url_for # type: ignore
from flask_session import Session # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash # type: ignore

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

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

#Dashboard
@app.route("/")     #Dashboard
@login_required     #Dashboard
def index():
       #Dashboard
    expenses = db.execute(
        "SELECT id, user_id, amount, type, date"
        " FROM transactions"
        " WHERE user_id = ? AND type = ?", session['user_id'], "expense"
    )
    incomes = db.execute(
        "SELECT id, user_id, amount, type, date"
        " FROM transactions"
        " WHERE user_id = ? AND type = ?", session['user_id'], "income"
    )
    total_expenses = 0;
    for expense in expenses:
        total_expenses += expense['amount']

    print(total_expenses)
    total_income = 0
    for income in incomes:
        total_income += income['amount']
        
    print(total_income)
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", session['user_id']
    )
    print(user)
    balance = 0
    """
    grand_value = user[0]['cash']
    print(grand_value)
    for stock in transactions:
        if stock['total_price'] == None:
            stock['total_price'] = 0
            stock['total_shares'] = 0
            stock['price_per_share'] = 0
        grand_value += stock['total_price']
        print(f"Updated {grand_value}")
    print(f"ID {user[0]['id']}")
    """
    return render_template("index.html", user=user, total_income=total_income, total_expenses=total_expenses, balance=balance)


 

@app.route("/add_transaction", methods=["GET", "POST"])
@login_required
def add_transaction():
    income_categories = ["Salary", "Business", "Investment", "Gift", "Other"]
    expense_categories = ["Groceries", "Rent", "Utilities", "Entertainment", "Transport", "Other"]

    if request.method == "POST":
        amount = request.form.get("amount")
        amount = int(amount)
        trans_type = request.form.get("type")
        category = request.form.get("category")
        date = request.form.get("date")
        user_id = session['user_id']
        
        if not amount or amount < 0:
            flash("You must specify an amount", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)

        if not trans_type:
            flash("You must specify a transaction type", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)

        if not category:
            flash("Category is required", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)

        if not date:
            flash("Enter a valid date", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)
        
        db.execute(
            "BEGIN TRANSACTION"
        )
        try:
            db.execute(
                "INSERT INTO transactions (user_id, amount, type, category, date)"
                "VALUES (?, ?, ?, ?, ?)", user_id, amount, trans_type, category, date
            )
            db.execute(
                "COMMIT"
            )
        except Exception as e:
            db.execute (
                "ROLLBACK"
            )
            print(e)
            flash("Failed", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)
            
            
        flash("Transaction added successfully", "success")
        return render_template("index.html")
    return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")



@app.route('/login', methods=['GET', 'POST'])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username", "info")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password", "info")
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("invalid username and/or password", "info")
            return render_template("login.html")

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


@app.route("/view_transactions", methods=["GET", "POST"])
@login_required
def view_transactions():
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        username = html.escape(username)
        password = request.form.get("password")
        conf_pass = request.form.get("confirmation")

        if not username:
            return apology("Empty username field", 400)
        if not password or not conf_pass:
            return apology("Empty password field", 400)
        if password != conf_pass:
            return apology("Password do not match", 400)
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )
        if rows:
            return apology("Username already taken")
        hashed_password = generate_password_hash(password)

        rows = db.execute(
            "INSERT INTO users (username, hash) VALUES( ?, ?)", username, hashed_password
        )
        user = db.execute(
            "SELECT id, username FROM users WHERE username = (?)", username
        )
        session["user_id"] = user[0]["id"]
        session["username"] = user[0]["username"]
        flash("Registered Successfully", "112.0")
        return redirect("/")

    return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
