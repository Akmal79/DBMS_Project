import sqlite3

def create_tables():
    # Using 'with' ensures that the connection is closed properly
    with sqlite3.connect('db.db') as connection:
        cursor = connection.cursor()

        # Create User table
        cursor.execute('''CREATE TABLE IF NOT EXISTS User (
                            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE,
                            password TEXT,
                            role TEXT CHECK(role IN ('User', 'Admin')),
                            email TEXT UNIQUE,
                            contact_number TEXT
                        )''')

        # Create Income table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Income (
                            income_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            source TEXT,
                            amount REAL CHECK(amount > 0),
                            date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Create Budget table (with start_date and end_date)
        cursor.execute('''CREATE TABLE IF NOT EXISTS Budget (
                            budget_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            category TEXT,
                            amount REAL CHECK(amount > 0),
                            start_date DATE,
                            end_date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Create Expense table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Expense (
                            expense_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            category TEXT,
                            amount REAL CHECK(amount > 0),
                            date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Create Goals table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Goals (
                            goal_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            goal_name TEXT,
                            target_amount REAL CHECK(target_amount > 0),
                            current_amount REAL CHECK(current_amount >= 0),
                            target_date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Create Loan table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Loan (
                            loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            loan_type TEXT,
                            amount REAL CHECK(amount > 0),
                            interest_rate REAL CHECK(interest_rate >= 0),
                            start_date DATE,
                            end_date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Create Investment table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Investment (
                            investment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            investment_type TEXT,
                            amount REAL CHECK(amount > 0),
                            interest_rate REAL CHECK(interest_rate >= 0),
                            start_date DATE,
                            FOREIGN KEY (user_id) REFERENCES User(user_id)
                        )''')

        # Commit the changes to the database
        connection.commit()

if __name__ == '__main__':
    create_tables()
