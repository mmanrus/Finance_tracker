import os
import html
from datetime import datetime
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
    data = fetch_dashboard_data()
    return render_template("index.html", user=data['user'], total_income=data['total_income'], total_expenses=data['total_expenses'], balance=data['balance'])

 

@app.route("/add_transaction", methods=["GET", "POST"])
@login_required
def add_transaction():
    income_categories = ["Salary", "Business", "Investment", "Gift"]
    expense_categories = ["Groceries", "Rent", "Utilities", "Entertainment", "Transport"]
    user_id = session['user_id']
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', user_id
        )
    if request.method == "POST":
        amount = request.form.get("amount")
        try:
            amount = float(amount)
        except ValueError as e:
            flash("Transaction failed", "failed")
            return render_template("profile.html", user=user)
        trans_type = request.form.get("type")
        category = request.form.get("category")
        date = request.form.get("date")
        user_id = session['user_id']
        
        if not amount or amount < 0:
            flash("You must specify an amount", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)

        if not trans_type:
            flash("You must specify a transaction type", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)

        if not category:
            flash("Category is required", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)

        if not date:
            flash("Enter a valid date", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)
        
        db.execute("BEGIN TRANSACTION")
        try:
            db.execute(
                "INSERT INTO transactions (user_id, amount, type, category, date)"
                "VALUES (?, ?, ?, ?, ?)", user_id, amount, trans_type, category, date
            )
            # Get the last inserted transaction ID
            transaction_id = db.execute("SELECT last_insert_rowid() AS id")[0]['id']
            if trans_type == 'expense':
                db.execute (
                    "UPDATE users SET cash = cash - ? WHERE id = ?", amount, session['user_id']
                )
            else:
                db.execute (
                    "UPDATE users SET cash = cash + ? WHERE id = ?", amount, session['user_id']
                )
            # Prepare history entry
            change_type = "Create"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db.execute(
                "INSERT INTO transaction_history (transaction_id, amount, type, category, date, user_id, change_type, timestamp)"
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                ,transaction_id, amount, trans_type, category, date, user_id, change_type, timestamp
            )
            db.execute(
                "COMMIT"
            )
            flash("Transaction added successfully", "success")
            data = fetch_dashboard_data()
            return render_template("index.html", user=data['user'], total_income=data['total_income'], total_expenses=data['total_expenses'], balance=data['balance'])

        except Exception as e:
            db.execute("ROLLBACK")
            print(e)
            flash("Failed", "info")
            return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)
            
            
    return render_template("add_transaction.html", income_categories=income_categories , expense_categories = expense_categories, user=user)


@app.route("/view_transaction")
@login_required
def view_transaction():
    user_id = session['user_id']
    user_transactions = db.execute(
        "SELECT * FROM transaction_history WHERE user_id = ?", user_id
    )
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", user_id
    )
    
    for transaction in user_transactions:
        transaction['date'] = datetime.strptime(transaction['date'], '%Y-%m-%d')
        
    return render_template("view_transaction.html", user_transactions=user_transactions, user=user)



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


@app.route("/reports", methods=["GET"])
@login_required
def reports():
    # Fetch data from the database
    user_id = session['user_id']
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", user_id
    )
    
    # Fetch all transactions
    transactions = db.execute(
        "SELECT id, user_id, amount, type, category, date FROM transactions WHERE user_id = ?", user_id
    )
    
    # Aggregate data
    income_by_category = {}
    expense_by_category = {}
    total_income = 0
    total_expenses = 0
    
    for transaction in transactions:
        if transaction['type'] == 'income':
            total_income += transaction['amount']
            if transaction['category'] not in income_by_category:
                income_by_category[transaction['category']] = 0
            income_by_category[transaction['category']] += transaction['amount']
        elif transaction['type'] == 'expense':
            total_expenses += transaction['amount']
            if transaction['category'] not in expense_by_category:
                expense_by_category[transaction['category']] = 0
            expense_by_category[transaction['category']] += transaction['amount']
    
    balance = total_income - total_expenses
    
    # Render the template with the data
    return render_template(
        "reports.html",
        income_by_category=income_by_category,
        expense_by_category=expense_by_category,
        total_income=total_income,
        total_expenses=total_expenses,
        balance=balance,
        user=user
    )
    
@app.route("/profile/<id>", methods=["GET", "POST"])
@login_required
def profile(id):

    user = db.execute("SELECT * FROM users WHERE id = ?", (id,))
    if not user:
        return apology("User not found", 403)

    if request.method == "POST":
        username = request.form.get("username")
        new_password = request.form.get("new-password")
        repeat_password = request.form.get("repeat-password")
        current_password = request.form.get("current-password")

        if not check_password_hash(
            user[0]["hash"], current_password
        ):
            flash("Password do not match", "failed")
            return render_template("profile.html", user=user)
        # Check if username is being changed
        if username and username != user[0]['username']:
            # Check if the new username is available
            rows = db.execute(
                "SELECT * FROM users WHERE username = ?", username
            )
            if rows:
                flash("Username already taken", "failed")
                return render_template("profile.html", user=user)
            else:
                # Update username in the database
                db.execute(
                    "UPDATE users SET username = ? WHERE id = ?", username, id
                )
                db.execute(
                    "COMMIT"
                )
                flash("Username updated successfully", "success")

        # Check if new password is being changed
        if new_password:
            if new_password != repeat_password:
                return apology("Passwords do not match", 403)
            else:
                # Hash and update the new password in the database
                hashed_password = generate_password_hash(new_password)
                db.execute(
                    "BEGIN TRANSACTION"
                )
                db.execute(
                    "UPDATE users SET hash = ? WHERE id = ?", hashed_password, id
                )
                db.execute(
                    "COMMIT"
                )
                flash("Password updated successfully", "success")

        return redirect('/')
    return render_template("profile.html", user=user)

@app.route('/add_balance/<id>', methods=['POST'])
def add_balance(id):
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', id
    )
    if request.method == "POST":
        amount = request.form.get('balance')
        try:
            amount = float(amount)
        except ValueError as e:
            flash(e, "failed")
            return render_template("profile.html", user=user)
        if not amount or amount < 0:
            flash("Please specify an amount", "failed")
            return render_template("profile.html", user=user)
        db.execute (
                    "UPDATE users SET cash = cash + ? WHERE id = ?", amount, session['user_id']
                )
        
        flash("Successfully added balance")
        return redirect('/')

    return render_template("profile.html", user=user)
def fetch_dashboard_data():
    user_id = session['user_id']
    expenses = db.execute(
        "SELECT id, user_id, amount, type, date"
        " FROM transactions"
        " WHERE user_id = ? AND type = ?", user_id, "expense"
    )
    incomes = db.execute(
        "SELECT id, user_id, amount, type, date"
        " FROM transactions"
        " WHERE user_id = ? AND type = ?", user_id, "income"
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
        "SELECT * FROM users WHERE id = ?", user_id
    )
    print(user)
    balance = user[0]['cash']
    balance -= total_expenses
    balance += total_income
    
    return {
        'user': user,
        'total_income': total_income,
        'total_expenses': total_expenses,
        'balance': balance
    }
