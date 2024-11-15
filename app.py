from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging

app = Flask(__name__)
app.secret_key = "your_secret_key"
def get_db_connection():
    conn = sqlite3.connect('db.db')
    conn.row_factory = sqlite3.Row
    return conn
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('home'))  
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        contact_number = request.form['contact_number']
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('db.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM User WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        cursor.execute("SELECT * FROM User WHERE email = ?", (email,))
        existing_email = cursor.fetchone()
        if existing_user:
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))
        if existing_email:
            flash('Email already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))
        cursor.execute(''' 
            INSERT INTO User (username, password, email, contact_number, role) 
            VALUES (?, ?, ?, ?, 'User')
        ''', (username, hashed_password, email, contact_number))
        conn.commit()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'Admin':
            flash('Admin access required.', 'warning')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function
    
@app.route('/user/view')
@admin_required
def view_user():
    conn = get_db_connection()
    records = conn.execute('SELECT * FROM User').fetchall()  # Fetch all users
    conn.close()
    return render_template('view_user.html', records=records)
@app.route('/user/add', methods=['GET', 'POST'])
@admin_required  
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        contact_number = request.form['contact_number']
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('db.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO User (username, password, email, contact_number, role)
            VALUES (?, ?, ?, ?, 'User')
        ''', (username, hashed_password, email, contact_number))
        conn.commit()
        conn.close()
        
        flash('User added successfully!', 'success')
        return redirect(url_for('view_user'))  # Redirect to the user list page
    return render_template('add_user.html')  # Render the form for adding a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Logic to delete the user by user_id
    conn = get_db_connection()
    conn.execute('DELETE FROM User WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('view_user'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM User WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']
            session['role'] = user['role']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))
@app.route('/home')
@login_required  
def home():
    return render_template('home.html')  
@app.route('/view_<table>')
@admin_required  # Ensure only admin users can access
def view_table(table):
    conn = get_db_connection()
    records = conn.execute(f"SELECT * FROM {table}").fetchall()  # Use parameterized queries if needed
    conn.close()
    # Pass the table name and records to the template
    return render_template('view_table.html', table=table, records=records)

@app.route('/investment', methods=['GET'])
@login_required
def view_investment():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')  # Get the current logged-in user's ID
    role = session.get('role')  # Check the user's role
    conn = get_db_connection()
    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Investment WHERE investment_type LIKE ? OR amount LIKE ?
            """
            investments = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            # Regular users can only search their own records
            query = """
                SELECT * FROM Investment WHERE user_id = ? AND (investment_type LIKE ? OR amount LIKE ?)
            """
            investments = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            investments = conn.execute('SELECT * FROM Investment').fetchall()
        else:
            investments = conn.execute('SELECT * FROM Investment WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('view_investment.html', investments=investments, search_query=search_query)
@app.route('/investment/add', methods=['GET', 'POST'])
@login_required
def add_investment():
    if request.method == 'POST':
        user_id = session['user_id']  # Automatically use logged-in user_id
        investment_type = request.form['investment_type']
        amount = request.form['amount']
        interest_rate = request.form['interest_rate']
        start_date = request.form['start_date']

        conn = get_db_connection()
        conn.execute('INSERT INTO Investment (user_id, investment_type, amount, interest_rate, start_date) VALUES (?, ?, ?, ?, ?)',
                     (user_id, investment_type, amount, interest_rate, start_date))
        conn.commit()
        conn.close()

        flash('Investment added successfully!')
        return redirect(url_for('view_investment'))
    return render_template('add_investment.html')

@app.route('/investment/edit/<int:investment_id>', methods=['GET', 'POST'])
@login_required
def edit_investment(investment_id):
    user_id = session['user_id']
    conn = get_db_connection()
    investment = conn.execute('SELECT * FROM Investment WHERE investment_id = ? AND user_id = ?', (investment_id, user_id)).fetchone()
    
    if investment is None:
        flash('Investment not found or you do not have permission to edit this investment.', 'danger')
        return redirect(url_for('view_investment'))

    if request.method == 'POST':
        investment_type = request.form['investment_type']
        amount = request.form['amount']
        interest_rate = request.form['interest_rate']
        start_date = request.form['start_date']

        conn.execute('UPDATE Investment SET investment_type = ?, amount = ?, interest_rate = ?, start_date = ? WHERE investment_id = ?',
                     (investment_type, amount, interest_rate, start_date, investment_id))
        conn.commit()
        conn.close()

        flash('Investment updated successfully!')
        return redirect(url_for('view_investment'))
    conn.close()
    return render_template('edit_investment.html', investment=investment)
@app.route('/investment/delete/<int:investment_id>', methods=['POST'])
@login_required
def delete_investment(investment_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Investment WHERE investment_id = ? AND user_id = ?', (investment_id, user_id))
    conn.commit()
    conn.close()
    flash('Investment deleted successfully!')
    return redirect(url_for('view_investment'))
@app.route('/expense', methods=['GET'])
@login_required
def view_expense():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')
    role = session.get('role')
    conn = get_db_connection()
    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Expense WHERE category LIKE ? OR amount LIKE ?
            """
            expenses = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            query = """
                SELECT * FROM Expense WHERE user_id = ? AND (category LIKE ? OR amount LIKE ?)
            """
            expenses = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            expenses = conn.execute('SELECT * FROM Expense').fetchall()
        else:
            expenses = conn.execute('SELECT * FROM Expense WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('view_expense.html', records=expenses, search_query=search_query)

@app.route('/expense/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        user_id = session['user_id']  # Automatically use logged-in user_id
        category = request.form['category']
        amount = request.form['amount']
        date = request.form['date']
        conn = get_db_connection()
        conn.execute('INSERT INTO Expense (user_id, category, amount, date) VALUES (?, ?, ?, ?)',
                     (user_id, category, amount, date))
        conn.commit()
        conn.close()
        flash('Expense added successfully!')
        return redirect(url_for('view_expense'))
    return render_template('add_expense.html')

@app.route('/expense/delete/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Expense WHERE expense_id = ? AND user_id = ?', (expense_id, user_id))
    conn.commit()
    conn.close()
    flash('Expense deleted successfully!')
    return redirect(url_for('view_expense'))
@app.route('/income', methods=['GET'])
@login_required
def view_income():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')  
    role = session.get('role')  
    conn = get_db_connection()
    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Income WHERE source LIKE ? OR amount LIKE ?
            """
            incomes = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            query = """
                SELECT * FROM Income WHERE user_id = ? AND (source LIKE ? OR amount LIKE ?)
            """
            incomes = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            incomes = conn.execute('SELECT * FROM Income').fetchall()
        else:
            incomes = conn.execute('SELECT * FROM Income WHERE user_id = ?', (user_id,)).fetchall()

    conn.close()
    return render_template('view_income.html', records=incomes, search_query=search_query)
@app.route('/income/add', methods=['GET', 'POST'])
@login_required
def add_income():
    if request.method == 'POST':
        user_id = session['user_id']  # Automatically use logged-in user_id
        amount = request.form['amount']
        source = request.form['source']  # Get the source input value
        date = request.form['date']
        conn = get_db_connection()
        conn.execute('INSERT INTO Income (user_id, source, amount, date) VALUES (?, ?, ?, ?)',
                     (user_id, source, amount, date))  # Add 'source' to the query
        conn.commit()
        conn.close()
        flash('Income added successfully!')
        return redirect(url_for('view_income'))
    return render_template('add_income.html')
@app.route('/income/edit/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    user_id = session['user_id']
    conn = get_db_connection()
    income = conn.execute('SELECT * FROM Income WHERE income_id = ? AND user_id = ?', (income_id, user_id)).fetchone()
    if income is None:
        flash('Income not found or you do not have permission to edit this income.', 'danger')
        return redirect(url_for('view_income'))
    if request.method == 'POST':
        amount = request.form['amount']
        source = request.form['source']
        date = request.form['date']
        conn.execute('UPDATE Income SET amount = ?, source = ?, date = ? WHERE income_id = ?',
                     (amount, source, date, income_id))
        conn.commit()
        conn.close()
        flash('Income updated successfully!')
        return redirect(url_for('view_income'))
    conn.close()
    return render_template('edit_income.html', income=income)
# Delete Income
@app.route('/income/delete/<int:income_id>', methods=['POST'])
@login_required
def delete_income(income_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Income WHERE income_id = ? AND user_id = ?', (income_id, user_id))
    conn.commit()
    conn.close()
    flash('Income deleted successfully!')
    return redirect(url_for('view_income'))
@app.route('/loan', methods=['GET'])
@login_required
def view_loan():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')  # Get the current logged-in user's ID
    role = session.get('role')  # Check the user's role
    conn = get_db_connection()
    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Loan WHERE loan_type LIKE ? OR amount LIKE ?
            """
            loans = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            query = """
                SELECT * FROM Loan WHERE user_id = ? AND (loan_type LIKE ? OR amount LIKE ?)
            """
            loans = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            loans = conn.execute('SELECT * FROM Loan').fetchall()
        else:
            loans = conn.execute('SELECT * FROM Loan WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return render_template('view_loan.html', loans=loans, search_query=search_query)
@app.route('/loan/add', methods=['GET', 'POST'])
@login_required
def add_loan():
    if request.method == 'POST':
        user_id = session['user_id']  # Automatically use logged-in user_id
        loan_type = request.form['loan_type']
        amount = request.form['amount']
        interest_rate = request.form['interest_rate']
        start_date = request.form['start_date']
        conn = get_db_connection()
        conn.execute('INSERT INTO Loan (user_id, loan_type, amount, interest_rate, start_date) VALUES (?, ?, ?, ?, ?)',
                     (user_id, loan_type, amount, interest_rate, start_date))
        conn.commit()
        conn.close()
        flash('Loan added successfully!')
        return redirect(url_for('view_loan'))
    return render_template('add_loan.html')
@app.route('/loan/edit/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def edit_loan(loan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    loan = conn.execute('SELECT * FROM Loan WHERE loan_id = ? AND user_id = ?', (loan_id, user_id)).fetchone()
    if loan is None:
        flash('Loan not found or you do not have permission to edit this loan.', 'danger')
        return redirect(url_for('view_loan'))
    if request.method == 'POST':
        loan_type = request.form['loan_type']
        amount = request.form['amount']
        interest_rate = request.form['interest_rate']
        start_date = request.form['start_date']
        conn.execute('UPDATE Loan SET loan_type = ?, amount = ?, interest_rate = ?, start_date = ? WHERE loan_id = ?',
                     (loan_type, amount, interest_rate, start_date, loan_id))
        conn.commit()
        conn.close()
        flash('Loan updated successfully!')
        return redirect(url_for('view_loan'))
    conn.close()
    return render_template('edit_loan.html', loan=loan)
@app.route('/loan/delete/<int:loan_id>', methods=['POST'])
@login_required
def delete_loan(loan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Loan WHERE loan_id = ? AND user_id = ?', (loan_id, user_id))
    conn.commit()
    conn.close()
    flash('Loan deleted successfully!')
    return redirect(url_for('view_loan'))
@app.route('/budget', methods=['GET'])
@login_required
def view_budget():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')  # Get the current logged-in user's ID
    role = session.get('role')  # Check the user's role
    conn = get_db_connection()
    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Budget WHERE category LIKE ? OR amount LIKE ?
            """
            budgets = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            query = """
                SELECT * FROM Budget WHERE user_id = ? AND (category LIKE ? OR amount LIKE ?)
            """
            budgets = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            budgets = conn.execute('SELECT * FROM Budget').fetchall()
        else:
            budgets = conn.execute('SELECT * FROM Budget WHERE user_id = ?', (user_id,)).fetchall()

    conn.close()
    return render_template('view_budget.html', budgets=budgets, search_query=search_query)
@app.route('/budget/add', methods=['GET', 'POST'])
@login_required
def add_budget():
    if request.method == 'POST':
        user_id = session['user_id'] 
        category = request.form.get('category')
        amount = request.form.get('amount')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if not category or not amount or not start_date or not end_date:
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_budget'))

        try:
            amount = float(amount)  # Ensure the amount is a number
            if amount <= 0:
                flash('Amount must be a positive number!', 'danger')
                return redirect(url_for('add_budget'))
        except ValueError:
            flash('Amount must be a valid number!', 'danger')
            return redirect(url_for('add_budget'))

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO Budget (user_id, category, amount, start_date, end_date) VALUES (?, ?, ?, ?, ?)',
                         (user_id, category, amount, start_date, end_date))
            conn.commit()
            flash('Budget added successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while adding the budget: {e}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('view_budget'))

    return render_template('add_budget.html')

@app.route('/budget/edit/<int:budget_id>', methods=['GET', 'POST'])
@login_required
def edit_budget(budget_id):
    user_id = session['user_id']
    conn = get_db_connection()
    budget = conn.execute('SELECT * FROM Budget WHERE budget_id = ? AND user_id = ?', (budget_id, user_id)).fetchone()
    if budget is None:
        flash('Budget not found or you do not have permission to edit this budget.', 'danger')
        conn.close()
        return redirect(url_for('view_budget'))
    if request.method == 'POST':
        category = request.form.get('category')
        amount = request.form.get('amount')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        if not category or not amount or not start_date or not end_date:
            flash('All fields are required!', 'danger')
            return redirect(url_for('edit_budget', budget_id=budget_id))

        try:
            amount = float(amount)  # Ensure the amount is a number
            if amount <= 0:
                flash('Amount must be a positive number!', 'danger')
                return redirect(url_for('edit_budget', budget_id=budget_id))
        except ValueError:
            flash('Amount must be a valid number!', 'danger')
            return redirect(url_for('edit_budget', budget_id=budget_id))

        try:
            conn.execute('UPDATE Budget SET category = ?, amount = ?, start_date = ?, end_date = ? WHERE budget_id = ?',
                         (category, amount, start_date, end_date, budget_id))
            conn.commit()
            flash('Budget updated successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while updating the budget: {e}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('view_budget'))

    conn.close()
    return render_template('edit_budget.html', budget=budget)
@app.route('/budget/delete/<int:budget_id>', methods=['POST'])
@login_required
def delete_budget(budget_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Budget WHERE budget_id = ? AND user_id = ?', (budget_id, user_id))
    conn.commit()
    conn.close()
    flash('Budget deleted successfully!')
    return redirect(url_for('view_budget'))

@app.route('/goals', methods=['GET'])
@login_required
def view_goals():
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')
    role = session.get('role')
    conn = get_db_connection()

    if search_query:
        if role == 'Admin':
            query = """
                SELECT * FROM Goals WHERE goal_name LIKE ? OR target_amount LIKE ? OR current_amount LIKE ?
            """
            goals = conn.execute(query, ('%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%')).fetchall()
        else:
            query = """
                SELECT * FROM Goals WHERE user_id = ? AND (goal_name LIKE ? OR target_amount LIKE ? OR current_amount LIKE ?)
            """
            goals = conn.execute(query, (user_id, '%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%')).fetchall()
    else:
        if role == 'Admin':
            goals = conn.execute('SELECT * FROM Goals').fetchall()
        else:
            goals = conn.execute('SELECT * FROM Goals WHERE user_id = ?', (user_id,)).fetchall()

    conn.close()
    return render_template('view_goals.html', records=goals, search_query=search_query)
@app.route('/goals/add', methods=['GET', 'POST'])
@login_required
def add_goal():
    if request.method == 'POST':
        user_id = session['user_id']  # Automatically use logged-in user_id
        goal_name = request.form['goal_name']
        target_amount = float(request.form['target_amount'])  # Ensure amount is float
        current_amount = float(request.form['current_amount'])  # Ensure amount is float
        target_date = request.form['target_date']
        
        # Validation can be added here to ensure amounts are valid
        if target_amount <= 0 or current_amount < 0:
            flash("Invalid amounts, please check your input!")
            return redirect(url_for('add_goal'))
        
        conn = get_db_connection()
        conn.execute('INSERT INTO Goals (user_id, goal_name, target_amount, current_amount, target_date) VALUES (?, ?, ?, ?, ?)',
                     (user_id, goal_name, target_amount, current_amount, target_date))
        conn.commit()
        conn.close()

        flash('Goal added successfully!')
        return redirect(url_for('view_goals'))
    
    return render_template('add_goal.html')
@app.route('/goals/delete/<int:goal_id>', methods=['POST'])
@login_required
def delete_goal(goal_id):
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM Goals WHERE goal_id = ? AND user_id = ?', (goal_id, user_id))
    conn.commit()
    conn.close()

    flash('Goal deleted successfully!')
    return redirect(url_for('view_goals'))
@app.route('/goals/edit/<int:goal_id>', methods=['GET', 'POST'])
@login_required
def edit_goal(goal_id):
    user_id = session['user_id']
    conn = get_db_connection()

    if request.method == 'POST':
        goal_name = request.form['goal_name']
        target_amount = float(request.form['target_amount'])
        current_amount = float(request.form['current_amount'])
        target_date = request.form['target_date']

        if target_amount <= 0 or current_amount < 0:
            flash("Invalid amounts, please check your input!")
            return redirect(url_for('edit_goal', goal_id=goal_id))

        conn.execute('''
            UPDATE Goals SET goal_name = ?, target_amount = ?, current_amount = ?, target_date = ?
            WHERE goal_id = ? AND user_id = ?
        ''', (goal_name, target_amount, current_amount, target_date, goal_id, user_id))

        conn.commit()
        conn.close()

        flash('Goal updated successfully!')
        return redirect(url_for('view_goals'))

    goal = conn.execute('SELECT * FROM Goals WHERE goal_id = ? AND user_id = ?', (goal_id, user_id)).fetchone()
    conn.close()

    if goal is None:
        flash("Goal not found or you do not have permission to edit this goal.")
        return redirect(url_for('view_goals'))

    return render_template('edit_goal.html', goal=goal)


@app.route('/financial_analysis', methods=['GET'])
@login_required
def financial_analysis():
    user_id = session['user_id']  # Get the logged-in user's ID
    conn = get_db_connection()

    # Total Income
    total_income_query = "SELECT SUM(amount) FROM Income WHERE user_id = ?"
    total_income = conn.execute(total_income_query, (user_id,)).fetchone()[0] or 0.0

    # Total Expenses
    total_expenses_query = "SELECT SUM(amount) FROM Expense WHERE user_id = ?"
    total_expenses = conn.execute(total_expenses_query, (user_id,)).fetchone()[0] or 0.0

    # Total Investments
    total_investment_query = "SELECT SUM(amount) FROM Investment WHERE user_id = ?"
    total_investment = conn.execute(total_investment_query, (user_id,)).fetchone()[0] or 0.0

    # Total Loan Amount
    total_loans_query = "SELECT SUM(amount) FROM Loan WHERE user_id = ?"
    total_loans = conn.execute(total_loans_query, (user_id,)).fetchone()[0] or 0.0

    # Calculate Savings
    net_savings = total_income - total_expenses

    # Investment to Income ratio (if income > 0)
    if total_income > 0:
        investment_to_income_ratio = (total_investment / total_income) * 100
    else:
        investment_to_income_ratio = 0.0

    # Debt to Income ratio (if income > 0)
    if total_income > 0:
        debt_to_income_ratio = (total_loans / total_income) * 100
    else:
        debt_to_income_ratio = 0.0

    # Savings Rate (if income > 0)
    if total_income > 0:
        savings_rate = (net_savings / total_income) * 100
    else:
        savings_rate = 0.0

    # Monthly Trends Data from Income and Expense tables
    monthly_data_query_income = """
    SELECT strftime('%Y-%m', date) AS month, SUM(amount) AS income
    FROM Income
    WHERE user_id = ?
    GROUP BY month
    ORDER BY month;
    """

    monthly_data_query_expense = """
    SELECT strftime('%Y-%m', date) AS month, SUM(amount) AS expense
    FROM Expense
    WHERE user_id = ?
    GROUP BY month
    ORDER BY month;
    """

    # Fetch monthly income data
    monthly_income_data = conn.execute(monthly_data_query_income, (user_id,)).fetchall()
    monthly_income = {row['month']: row['income'] for row in monthly_income_data}

    # Fetch monthly expense data
    monthly_expense_data = conn.execute(monthly_data_query_expense, (user_id,)).fetchall()
    monthly_expenses = {row['month']: row['expense'] for row in monthly_expense_data}

    # Combine data and calculate monthly savings
    monthly_labels = sorted(set(monthly_income.keys()).union(monthly_expenses.keys()))
    monthly_income_values = [monthly_income.get(month, 0) for month in monthly_labels]
    monthly_expenses_values = [monthly_expenses.get(month, 0) for month in monthly_labels]
    monthly_savings = [income - expense for income, expense in zip(monthly_income_values, monthly_expenses_values)]

    conn.close()

    # Render the template with all calculated values
    return render_template(
        'financial_analysis.html', 
        total_income=total_income,
        total_expenses=total_expenses,
        total_investment=total_investment,
        total_loans=total_loans,
        net_savings=net_savings,
        investment_to_income_ratio=investment_to_income_ratio,
        debt_to_income_ratio=debt_to_income_ratio,
        savings_rate=savings_rate,
        monthly_labels=monthly_labels,
        monthly_income=monthly_income_values,
        monthly_expenses=monthly_expenses_values,
        monthly_savings=monthly_savings
    )

if __name__ == '__main__':
    app.run(debug=True)


