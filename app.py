from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# Initialize Flask app and configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secret key of your choice
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database setup
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# User and Task Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# User login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    task_title = request.form['task_title']
    new_task = Task(title=task_title, user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    flash('Task added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_task/<int:id>')
@login_required
def delete_task(id):
    task = Task.query.get(id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    else:
        flash('You can only delete your own tasks.', 'danger')
    return redirect(url_for('index'))

@app.route('/update_task/<int:id>', methods=['GET', 'POST'])
@login_required
def update_task(id):
    task = Task.query.get(id)
    if request.method == 'POST':
        task.completed = not task.completed
        db.session.commit()
        flash('Task status updated!', 'success')
        return redirect(url_for('index'))
    return render_template('update_task.html', task=task)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
        else:
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            login_user(new_user)
            return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Run app
if __name__ == '__main__':
    # Ensure the app context is set correctly to create the database
    with app.app_context():
        db.create_all()  # Create the database tables
    app.run(debug=True)
