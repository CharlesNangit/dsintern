from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Shared intern email (the one all interns will use)
SHARED_INTERN_EMAIL = "desksideintern@gmail.com"  # Replace with your actual shared Outlook email

# --- App Config ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'devsecret123'  # Change this later for security
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Email Config ---
app.config['SENDGRID_API_KEY'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_SENDER'] = "desksideintern@dsintern.com"  # safer domain for Outlook delivery
app.config['MAIL_REPLY_TO'] = "desksideintern@gmail.com"   # where replies go

# --- User Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='intern')  # 'admin' or 'intern'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

login_manager.session_protection = "strong"
login_manager.login_message_category = "info"

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'intern'

        # Force use of shared intern email domain
        if email != SHARED_INTERN_EMAIL:
            flash(f'Invalid email. All interns must register using {SHARED_INTERN_EMAIL}.', 'danger')
            return redirect(url_for('register'))

        # Make each intern’s email unique internally
        unique_email = f"{name.lower()}_{email}"

        existing_user = User.query.filter_by(email=unique_email).first()
        if existing_user:
            flash('This intern name already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=unique_email, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Intern registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        print(f"🟩 Received Login Data:\nName: {name}\nEmail: {email}\nPassword: {password}")

        if email == SHARED_INTERN_EMAIL:
            # Intern login: match by name + shared email
            unique_email = f"{name.lower()}_{email}"
            user = User.query.filter_by(email=unique_email).first()
        else:
            # Admin login: use their actual email
            user = User.query.filter_by(email=email).first()

        print(f"🟩 User Found: {user}")

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            print(f"✅ Redirecting to dashboard for: {user.role}")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('intern_dashboard'))
        else:
            print("❌ Invalid login")
            flash('Invalid login credentials', 'danger')

    return render_template('login.html')



@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', user=current_user)

@app.route('/intern_dashboard')
@login_required
def intern_dashboard():
    if current_user.role != 'intern':
        flash('Access denied: Interns only.', 'danger')
        return redirect(url_for('login'))
    return render_template('intern_dashboard.html', user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    return f"<h2>Welcome, {current_user.name}! Role: {current_user.role}</h2>"

# --- Email Pool Model ---
class EmailRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)

# --- Admin-only routes ---
@app.route('/create_admin')
def create_admin():
    # Only allow this once, then remove or disable it!
    existing_admin = User.query.filter_by(role='admin').first()
    if existing_admin:
        return "Admin already exists. Delete this route after use."

    hashed_pw = bcrypt.generate_password_hash("DesksideAdmin101").decode('utf-8')
    admin = User(name="Admin", email="DSAdmin@nexus.com", password=hashed_pw, role="admin")
    db.session.add(admin)
    db.session.commit()
    return "✅ Admin account created!"

@app.route('/manage_emails', methods=['GET', 'POST'])
@login_required
def manage_emails():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_email = request.form['email']
        if not new_email:
            flash('Email field cannot be empty.', 'warning')
        else:
            existing = EmailRecipient.query.filter_by(email=new_email).first()
            if existing:
                flash('Email already exists in pool.', 'warning')
            else:
                db.session.add(EmailRecipient(email=new_email))
                db.session.commit()
                flash('Email added successfully.', 'success')

    emails = EmailRecipient.query.all()
    return render_template('manage_emails.html', emails=emails)

@app.route('/manage_interns', methods=['GET', 'POST'])
@login_required
def manage_interns():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    interns = User.query.filter_by(role='intern').all()
    return render_template('manage_interns.html', interns=interns)


@app.route('/delete_intern/<int:id>', methods=['POST'])
@login_required
def delete_intern(id):
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    intern = User.query.get_or_404(id)
    if intern.role != 'intern':
        flash('You can only delete intern accounts.', 'warning')
        return redirect(url_for('manage_interns'))

    db.session.delete(intern)
    db.session.commit()
    flash(f'Intern "{intern.name}" deleted successfully.', 'info')
    return redirect(url_for('manage_interns'))

@app.route('/delete_email/<int:id>')
@login_required
def delete_email(id):
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    email_to_delete = EmailRecipient.query.get_or_404(id)
    db.session.delete(email_to_delete)
    db.session.commit()
    flash('Email deleted successfully.', 'info')
    return redirect(url_for('manage_emails'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/send_report', methods=['GET', 'POST'])
@login_required
def send_report():
    if current_user.role != 'intern':
        flash('Only interns can send reports.', 'danger')
        return redirect(url_for('dashboard'))

    recipients = EmailRecipient.query.all()

    if request.method == 'POST':
        selected_emails = request.form.getlist('recipients')
        subject = request.form.get('subject')
        body = request.form.get('body')
        image_base64 = request.form.get('image_base64')

        if not selected_emails or not subject or not body:
            flash('Please fill in all fields before sending.', 'warning')
            return redirect(url_for('send_report'))

        # Create HTML table for the report
        html_content = f"""
        <html>
        <body style="font-family:Arial, sans-serif;">
          <h3 style="color:#333;">Deskside Diagnostic Report</h3>
          <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;max-width:600px;">
            <tr style="background-color:#f8f9fa;"><th>Intern Name</th><td>{current_user.name}</td></tr>
            <tr><th>Email</th><td>{current_user.email}</td></tr>
            <tr><th>Diagnostic Result</th><td>{body}</td></tr>
          </table>
        """

        if image_base64:
            html_content += f'<div style="margin-top:15px;"><strong>Attached Image:</strong><br><img src="{image_base64}" style="max-width:100%;border:1px solid #ccc;border-radius:8px;"></div>'

        html_content += "</body></html>"

        try:
            sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])

            for email_addr in selected_emails:
                message = Mail(
                    from_email=("desksideintern@dsintern.com", "Deskside Intern"),
                    to_emails=email_addr,
                    subject=subject,
                    html_content=html_content
                )
                message.reply_to = "desksideintern@gmail.com"
                response = sg.send(message)
                print(f"📨 Sent to {email_addr} | Status: {response.status_code}")

            flash(f'Report sent successfully to {len(selected_emails)} recipient(s).', 'success')

        except Exception as e:
            print(f"❌ Send error: {e}")
            flash(f'Failed to send emails: {e}', 'danger')

        return redirect(url_for('send_report'))

    return render_template('send_report.html', recipients=recipients)

# --- Ensure Tables Exist Even on Render Startup ---
with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created or verified successfully.")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")

# --- App Entry Point ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

