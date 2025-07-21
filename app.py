from flask import Flask, request, render_template,redirect, url_for,send_file,session
import qrcode
from flask_cors import CORS
import socket
import pyautogui
from datetime import timedelta,date,datetime
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flaskwebgui import FlaskUI
import waitress
import threading
from cryptography.fernet import Fernet
import uuid,subprocess,io,random,string
import time
import pandas as pd
import io
from io import BytesIO
from sqlalchemy import cast, Date, and_
from openpyxl.utils import get_column_letter
from flask import send_file
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask_mail import Mail, Message
import calendar
import os
from flask_bcrypt import Bcrypt

# import pdfkit
from flask_login  import UserMixin,LoginManager,login_user,logout_user,current_user,login_required

#pending imports
# from weasyprint import HTML


lock = threading.Lock()
fernet = Fernet(b'Dx3VuBA0JjXX164KBAlLUbqOA8EgYLMP6M842phMdkw=')
app = Flask(__name__,template_folder='templates',static_folder='static')
CORS(app)

port=5000
command = f"netsh advfirewall firewall add rule name=MyRule dir=in action=allow protocol=TCP localport={port} name=\"Flask App\""
subprocess.call(command, shell=True)


app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY']='thisisasecretkey'
app.config['SQLITE_ENCRYPTION_KEY'] = '17156165'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'bytebillreport@gmail.com'  
app.config['MAIL_PASSWORD'] = 'tmjyjwwjzpjuybhw' 

mail =  Mail(app)
bcrypt=Bcrypt(app)

db=SQLAlchemy()
db.init_app(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view ="login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Loggers, int(user_id))

class EmailPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    daily_email_enabled = db.Column(db.Boolean, default=False, nullable=False)
    daily_email_time = db.Column(db.Time, nullable=True)
    monthly_email_enabled = db.Column(db.Boolean, default=False, nullable=False)
    monthly_email_day = db.Column(db.Integer, nullable=True)
    yearly_email_enabled = db.Column(db.Boolean, default=False, nullable=False)
    yearly_email_day = db.Column(db.Integer, nullable=True)
    yearly_email_month = db.Column(db.Integer, nullable=True)
    studentemail =  db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, daily_email_enabled=False, daily_email_time=None, 
                 monthly_email_enabled=False, monthly_email_day=None, 
                 yearly_email_enabled=False, yearly_email_day=None, 
                 yearly_email_month=None, password=None,studentemail=False):
        self.daily_email_enabled = daily_email_enabled
        self.daily_email_time = daily_email_time
        self.monthly_email_enabled = monthly_email_enabled
        self.monthly_email_day = monthly_email_day
        self.yearly_email_enabled = yearly_email_enabled
        self.yearly_email_day = yearly_email_day
        self.yearly_email_month = yearly_email_month
        self.studentemail = studentemail

class LastEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # Daily email settings
    last_daily_email = db.Column(db.DateTime, nullable=True)  # Tracks the datetime of the last daily email
    # Monthly email settings
    last_monthly_email = db.Column(db.DateTime, nullable=True)  # Tracks the datetime of the last monthly email
    # Yearly email settings
    last_yearly_email = db.Column(db.DateTime, nullable=True)  # Tracks the datetime of the last yearly email
    

class Loggers(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),unique=True,nullable=False)
    password=db.Column(db.String(80),nullable=False)
    admin = db.Column(db.String(80))    
class User(db.Model):
    __tablename__='User'
    id=db.Column(db.Integer, primary_key=True)
    firm = db.Column(db.String(10))
    mobile = db.Column(db.String(10))
    email = db.Column(db.String(20),default='mundheajit001@gmail.com')
    address = db.Column(db.JSON,default=None)
    billleft = db.Column(db.String(20),default=None)
    billright = db.Column(db.String(20),default=None)
    billwarning = db.Column(db.JSON,default=None)
    key = db.Column(db.String(15),default=None)
    users = db.Column(db.JSON,default=None)
    # email allowed or not 1 or 0
    varv = db.Column(db.LargeBinary, default=b'gAAAAABkBuCHKUt7lJp7LzCqQnJr7c_SQ9a9WmxSoGgxgW5zuhwEYb6qBTzC5dUS7PgVRi1NcwgeUbFDJbxMgL0E_9p4ZEicYA==')
    # mac
    varm=db.Column(db.LargeBinary)
    # end date stored in this variable
    vare = db.Column(db.LargeBinary, default=b"gAAAAABkBkH7EXwVMYrlur24vC1Ce8KxfuV_wZM_COoio7vGVYQ5vvMXnxWVI-aajZ5xeGe5xZcOtRSBtrV7r98kORYGJnvg5A==")
    # last subscription date
    varl = db.Column(db.LargeBinary, default=b"gAAAAABkA4Ec0AwRkH5fskaHumhNj7rX-wpeC_49LZg7QtyOcoT8WNX44HX46Hh4lv5As3R4T77kZpw4xPaGJBF0wnkZUs5szQ==")
    # only studypoint to show
    varss = db.Column(db.LargeBinary, default=b'gAAAAABkBuCHKUt7lJp7LzCqQnJr7c_SQ9a9WmxSoGgxgW5zuhwEYb6qBTzC5dUS7PgVRi1NcwgeUbFDJbxMgL0E_9p4ZEicYA==')
class Payment(db.Model):
    __tablename__ = "Payment"
    srno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    aadhar = db.Column(db.BigInteger)
    amount = db.Column(db.Integer)
    payment = db.Column(db.String)
    course = db.Column(db.String)
    date = db.Column(db.String(20))
    study=db.Column(db.Boolean,default=False)
    user=db.Column(db.String(20),default=None)
class Study(db.Model):
    __tablename__='Study'
    srno = db.Column(db.Integer, primary_key=True)
    seats = db.Column(db.Integer)
    seatlist=db.Column(db.JSON)
    fee = db.Column(db.Integer)
class Studypoint(db.Model):
    __tablename__='Studypoint'
    srno = db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String(20))
    aadhar = db.Column(db.BigInteger)
    email = db.Column(db.String(20),default=None)
    seatalloted=db.Column(db.Integer)
    mobile = db.Column(db.BigInteger)
    firstdate=db.Column(db.String(20),default=None)
    lastdate=db.Column(db.String(20),default=None)

    
def genkey():
    characters = string.ascii_letters + string.digits + ("$#@&*")
    key = ''.join(random.choice(characters) for x in range(10))
    return key


def get_mac_address():
    output = subprocess.check_output("wmic cpu get ProcessorId", shell=True)
    output = output.decode("utf-8").strip().split("\n")[1]
    return output

def encryptf(message):
    encoded_message = message.encode()
    encrypted_message = fernet.encrypt(encoded_message)
    return encrypted_message


def decryptf(encrypted_message):
    decrypted_message = fernet.decrypt(encrypted_message)
    decoded_message = decrypted_message.decode()
    return decoded_message



def get_wifi_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # Connect to Google Public DNS
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address


def save_qr():
    ip_address = get_wifi_ip_address()
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(ip_address)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save("static/qr_code.png")


def excelreport(start,end):
    userstotal={}
    data={}
    payment = Payment.query.all() 
    payments = [payment for payment in payment 
                    if datetime.strptime(payment.date, '%Y-%m-%d').date() >= start 
                    and datetime.strptime(payment.date, '%Y-%m-%d').date() <= end]  
    for i in payments:
        if i.course:
            if i.user not in userstotal:
                userstotal[i.user]=0
            userstotal[i.user]+=i.amount     
    student= Studypoint.query.all()
    studypoint = Studypoint.query.all()
    for i in payments:
        if i.study:
            k = {
                'Bill No': [payment.srno for payment in payments  if payment.study ],
                'Student ': [payment.name for payment in payments if payment.study ],
                'Aadhar' :[payment.aadhar for payment in payments if payment.study ],
                'Amount': [payment.amount for payment in payments  if payment.study ],
                'payment': [payment.payment for payment in payments  if payment.study ],
                'Payment Date': [payment.date for payment in payments  if payment.study ],
                'User': [payment.user if payment.user else None for payment in payments if payment.study]
            }
            if 'study' not in data:
                data['study']={}
            data['study']=k
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        for i in data:
            df=pd.DataFrame(data[i])
            total_amount = df['Amount'].sum()
            df['User'] = df['User'].fillna('Null')
            user_totals = df.groupby('User')['Amount'].sum()
            user_totals_dict = user_totals.to_dict()
            dafd={'Start Date': [start], 'End Date': [end], 'Total Amount':[total_amount]}
            for j in user_totals_dict :
                dafd[j]=user_totals_dict[j]
            date_info = pd.DataFrame(dafd)
            date_info.to_excel(writer, index=False, sheet_name=i, startrow=0)
            df.to_excel(writer, index=False, sheet_name=i,startrow=4)

            workbook = writer.book
            worksheet = writer.sheets[i]
            column_widths = [15, 40, 15, 8, 10, 15]  
            for idx, width in enumerate(column_widths, 1):  
                column_letter = get_column_letter(idx)
                worksheet.column_dimensions[column_letter].width = width

    output.seek(0)

    return output

def send_email():
    with app.app_context():
        user = User.query.first()
        msg = Message('Daily Report',
                      sender='bytebillreport@gmail.com',
                      recipients=[user.email])  # Adjust as needed
        msg.body = 'Here is your daily report'
        excel_file = excelreport((datetime.today() - timedelta(days=1)).date(),(datetime.today() - timedelta(days=1)).date())
        date_str = datetime.today().strftime('%Y-%m-%d')
        msg.attach(f'{date_str}_report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', excel_file.read())
        mail.send(msg)
        try:
            lastemail = LastEmail.query.first()
            lastemail.last_daily_email = date.today()
        except :
            lastemail = LastEmail(last_daily_email=date.today())
            db.session.add(lastemail)
        db.session.commit()


# def bill_pdf(srno):
#     payment = Payment.query.filter_by(srno=srno).one()
#     aadhar = payment.aadhar
#     student = Student.query.filter_by(aadhar=aadhar).first()
#     allpayments=Payment.query.filter_by(aadhar=aadhar).all()
#     user=User.query.first()
#     if payment.study:
#         studypoint = Studypoint.query.filter_by(aadhar=aadhar).first()
#         study=Study.query.first()
#         total=study.fee
#         paid=0
#         for i in allpayments:
#             if i.date <= payment.date and i.study :
#                 paid+=i.amount
#         due=total-paid
#         point=["studypoint",study.fee,studypoint.seatalloted]
#         page=render_template('reciept2.html',student=studypoint,payment=payment,due=due,paid=paid,point=point,user=user)   
#     else:
#         total=0
#         courses=student.courses
#         for i in courses:
#             if i==payment.course:
#                 total = courses[i]
#         paid=0
#         if allpayments:
#             for i in allpayments:
#                 if i.date <= payment.date and i.course == payment.course and i.srno <= payment.srno:
#                     paid+=i.amount
#             due=total-paid
#         else:
#             due=total-payment.amount
#         page=render_template('reciept2.html',allpayments=allpayments,student=student,payment=payment,due=due,paid=paid,courses=courses,user=user)         
#     html=HTML(string=page)
#     file_name=str(srno)+".pdf"
#     html.write_pdf(target=file_name)
#     print(file_name)
#     response = send_file(
#         file_name,
#         as_attachment=True,  # Set to False to open in browser
#         download_name=file_name,  # Custom download name
#         mimetype='application/pdf'
#     )
#     return response

def email_bill(srno):
    payment = Payment.query.filter_by(srno=srno).one()
    aadhar = payment.aadhar
    student = Studypoint.query.filter_by(aadhar=aadhar).first()
    allpayments=Payment.query.filter_by(aadhar=aadhar).all()
    user=User.query.first()
    if int(decryptf(user.varv)) == 1:
        studypoint = Studypoint.query.filter_by(aadhar=aadhar).first()
        study=Study.query.first()
        total=study.fee
        paid=0
        for i in allpayments:
            if i.date <= payment.date and i.study :
                paid+=i.amount
        due=total-paid
        point=["studypoint",study.fee,studypoint.seatalloted]
        page=render_template('reciept2.html',student=studypoint,payment=payment,due=due,paid=paid,point=point,user=user)  
        msg = Message('Payment Reciept',
                        sender='bytebillreport@gmail.com',
                        recipients=[student.email])  # Adjust as needed
        msg.body = f'Hello {student.name},\n Payment of rupees{payment.amount} for {payment.course} recieved'
        msg.html = page
        mail.send(msg)
        print('email_sent')
    



def send_email_month():
    with app.app_context():
        user = User.query.first()
        msg = Message('Monthly Report',
                      sender='bytebillreport@gmail.com',
                      recipients=[user.email])  # Adjust as needed
        msg.body = 'Here is your monthly report.'
        today=datetime.today().date()
        first_day_of_current_month = today.replace(day=1)
        last_month = first_day_of_current_month - timedelta(days=1)
        last_month_name = last_month_date.strftime('%B')
        first_day_of_previous_month = last_month.replace(day=1)
        end = today- timedelta(days=1)
        start = first_day_of_previous_month
        excel_file = excelreport(start,end)
        msg.attach(f'{last_month_name}_report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', excel_file.read())
        mail.send(msg)
        try:
            lastemail = LastEmail.query.first()
            lastemail.last_monthly_email = date.today()
        except :
            lastemail = LastEmail(last_monthly_email=date.today())
            db.session.add(lastemail)
        db.session.commit()
def send_email_year():
    with app.app_context():
        user = User.query.first()
        msg = Message('Yearly Report',
                      sender='bytebillreport@gmail.com',
                      recipients=[user.email]) 
        msg.body = 'Here is your yearly report.'
        today=datetime.today().date()
        end = today - timedelta(days=1)
        previous_year = today.year - 1
        start = date(previous_year, 4, 1)
        excel_file = excelreport(start,end)
        msg.attach('report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', excel_file.read())
        mail.send(msg)
        try:
            lastemail = LastEmail.query.first()
            lastemail.last_yearly_email = date.today()
        except :
            lastemail = LastEmail(last_yearly_email=date.today())
            db.session.add(lastemail)
        db.session.commit()
def send_custom_email(start,end):
    with app.app_context():
        user = User.query.first()
        msg = Message('Custom Report',
                      sender='bytebillreport@gmail.com',
                      recipients=[user.email])  # Adjust as needed
        msg.body = 'Here is your custom report'
        excel_file = excelreport(start,end)
        date_str = datetime.today().strftime('%Y-%m-%d')
        msg.attach(f'{date_str}_report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', excel_file.read())
        mail.send(msg)

scheduler = BackgroundScheduler()
scheduler.add_job(func=send_email, trigger=CronTrigger(hour=20, minute=00),id='daily_email')  # 5 PM
scheduler.add_job(func=send_email_month, trigger=CronTrigger(day=1, hour=20, minute=0), id='monthly_email')
scheduler.add_job(func=send_email_year, trigger=CronTrigger(month=4, day=1, hour=20, minute=0), id='yearly_email')

scheduler.start()



def check_emails_sent():
    try:
        # Fetch the first entry from the LastEmail table
        lastemail = LastEmail.query.first()
        if lastemail:
            # Get the current date
            today = date.today()
            yesterday = today - timedelta(days=1)
            first_day_of_this_month = today.replace(day=1)
            first_day_of_this_year = today.replace(month=1, day=1)

            # Check if last_daily_email_datetime is None or not yesterday
            if lastemail.last_daily_email != yesterday:
                # Call sendemail with the last email date and today's date
                send_custom_email(lastemail.last_daily_email, today)

                # Update last_daily_email_datetime to now
                lastemail.last_daily_email = today
            # if not lastemail.last_monthly_email or lastemail.last_monthly_email < first_day_of_this_month:
            #     send_email_month()
            #     lastemail.last_monthly_email = today

            # # Check and handle yearly email
            # if not lastemail.last_yearly_email or lastemail.last_yearly_email < first_day_of_this_year:
            #     send_email_year()
            #     lastemail.last_yearly_email = today

            db.session.commit()
        else:
            send_email()
    except Exception as e:
        print(f"An error occurred: {e}")
   

@app.route('/report',methods=['GET'])
@login_required
def report():
    user=User.query.first()
    if check():
        allpayments=Payment.query.all()
        collection=0
        coursewise={}
        userwise={}
        for i in allpayments:
            if i.date==str(datetime.today().date()) : 
                collection+=i.amount
                if i.course not in coursewise:
                    coursewise[i.course] = 0
                coursewise[i.course] += i.amount
                if i.user not in userwise:
                    userwise[i.user] = 0
                userwise[i.user] += i.amount
        return render_template('report.html',user=user,collection=collection,coursewise=coursewise,userwise=userwise)
    return redirect(url_for('index'))
def check():
    user = User.query.filter_by(id=1).first()  # Use .first() to get a single result
    if user:
        vare = decryptf(user.vare)
        li=vare.split('`')
        if get_mac_address() == str(li[0]) and str(user.key) == str(li[1]):
            end=li[-1]
        else:
            return False
        mac=decryptf(user.varm)
        payment = Payment.query.first()
        var= bool(int(decryptf(user.varv)))
        firmname = user.firm
        if mac==get_mac_address():
            if end and date.today() <= datetime.strptime(end, "%Y-%m-%d").date():
                if payment :
                    payment_date = datetime.strptime(payment.date, '%Y-%m-%d').date()
                    if datetime.today().date() < payment_date :
                        return False 
                return True
            else:
                return False
        return False
    return False

current_dir = os.path.dirname(os.path.abspath(__file__))
exe_path = os.path.join(current_dir, "ByteBill.exe")  # Replace 'your_app.exe' with the actual filename

# PowerShell command to create a scheduled task
command = f"""
$Action = New-ScheduledTaskAction -Execute '{exe_path}'
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount
Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName 'MyFlaskAppAutoStart' -Description 'Start Flask app at startup'
"""

# Run the command as a subprocess
subprocess.run(["powershell", "-Command", command], shell=True)


@app.route('/logout',methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/loggers/admin',methods=['GET','POST'])
@login_required
def loggersupdate():
    if request.method == 'GET':
        if decryptf(current_user.admin)=='1':
            firm=User.query.first()
            loggers=Loggers.query.all()
            return render_template('loggers.html',loggers=loggers,firm=firm)
        else:
            return render_template('error',error='chutiya ho ka be')
    elif request.method == 'POST':
        return Null
@app.route('/updatelogger/<int:idd>',methods=['GET','POST'])
@login_required
def updatelogger(idd):
    logger = Loggers.query.get(idd)
    firm=User.query.first()
    if request.method == 'GET':
        return render_template('update_logger.html',logger=logger,firm=firm)
    elif request.method == 'POST':
        logger.username = request.form.get('username')
        passw=request.form.get('password')
        if passw !='':
            logger.password = bcrypt.generate_password_hash(passw)
        db.session.commit()
        return redirect(url_for('settings'))

@app.route('/delete/logger/<int:id>',methods=['GET'])
@login_required
def deletelogger(id):
    logger = Loggers.query.get(id)
    if request.method == 'GET':
        db.session.delete(logger)
        db.session.commit()
        return redirect(url_for('index'))
        

@app.route('/register',methods=["GET","POST"])
@login_required
def register():
    firm=User.query.first()
    if request.method == "POST":
        username=request.form['username']
        password = request.form['password']
        usdn=Loggers.query.filter_by(username=username).first()
        if usdn:
            return render_template('register.html',a='alert',b='username already exist')
        hashed_password = bcrypt.generate_password_hash(password)
        new_user=Loggers(username=username,password=hashed_password,admin=encryptf('0'))
        db.session.add(new_user)
        db.session.commit()
        return redirect (url_for('index'))
    return render_template('register.html',firm=firm)


@app.route('/login',methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form['username']
        password = request.form['password']
        user=Loggers.query.filter_by(username=username).first()
        if user:
            if bcrypt.check_password_hash(user.password,password):
                login_user(user)
                return redirect(url_for('index'))
            else:
                return render_template('login.html',a='alert',b='wrong password')
        else:
            return render_template('login.html',a='alert',b='Username not found')
    else:
     return render_template('login.html')


@app.route('/updateemail/',methods=['GET','POST'])
def updateemail():
    if request.method =='GET':
        firm=User.query.first()
        entry = EmailPreferences.query.first()
        if entry:
            return render_template('updateemail.html',firm=firm,entry=entry)
        else:
            return render_template('updateemail.html',firm=firm,entry=None)

    elif request.method == 'POST':
        # Retrieve form data
        daily_email_enabled = 'daily_email_enabled' in request.form
        daily_email_time_str = request.form.get('daily_email_time') if daily_email_enabled else None
        try:
            daily_email_time = (
                datetime.strptime(daily_email_time_str, '%H:%M').time() if daily_email_time_str else None
            )
        except ValueError:  # Correct exception type
            daily_email_time = (
                datetime.strptime(daily_email_time_str, '%H:%M:%S').time() if daily_email_time_str else None
            )

        monthly_email_enabled = 'monthly_email_enabled' in request.form
        monthly_email_day = request.form.get('monthly_email_day') if monthly_email_enabled else None

        yearly_email_enabled = 'yearly_email_enabled' in request.form
        yearly_email_day = request.form.get('yearly_email_day') if yearly_email_enabled else None
        yearly_email_month = request.form.get('yearly_email_month') if yearly_email_enabled else None
        studentemail = 'studentemail' in request.form
            
         # Append new data to the table
        try:
            entry = EmailPreferences.query.first()
            entry.daily_email_enabled = daily_email_enabled
            
            if daily_email_time:
                 entry.daily_email_time = daily_email_time
            entry.monthly_email_enabled = monthly_email_enabled
            if monthly_email_day:
                entry.monthly_email_day = monthly_email_day
            entry.yearly_email_enabled = yearly_email_enabled
            if yearly_email_day:
                entry.yearly_email_day = yearly_email_day
            if yearly_email_month:
                entry.yearly_email_month = yearly_email_month
            entry.studentemail = studentemail
            db.session.commit()
        except Exception as e:
            new_entry = EmailPreferences(
                daily_email_enabled=daily_email_enabled,
                daily_email_time=daily_email_time,
                monthly_email_enabled=monthly_email_enabled,
                monthly_email_day=int(monthly_email_day) if monthly_email_day else None,
                yearly_email_enabled=yearly_email_enabled,
                yearly_email_day=int(yearly_email_day) if yearly_email_day else None,
                yearly_email_month=int(yearly_email_month) if yearly_email_month else None,
                studentemail=studentemail
            )

            db.session.add(new_entry)
            db.session.commit()
            
        return redirect(url_for('dashboard'))

    
@app.route('/update/studypoint/student/<int:aadharr>', methods=['GET', 'POST'])
@login_required
def updatestudystudent(aadharr):
    aadhar=aadharr
    if check():
        if request.method=="GET":
            study=Study.query.first()
            user=User.query.first()
            if study:
                studypoint=Studypoint.query.all()
                students=Studypoint.query.all()
                student=Studypoint.query.filter_by(aadhar=aadhar).one()
                nearexpiry={}
                available=int(study.seats)-int(len(studypoint))
                for i in studypoint:
                    if i.lastdate:
                        date_format = "%Y-%m-%d"
                        last_date = datetime.strptime(i.lastdate, date_format).date()
                        nearexpiry[i.aadhar]=(last_date - datetime.today().date()).days
                    else:
                        nearexpiry[i.aadhar]=0
                sorted_nearexpiry = {k: v for k, v in sorted(nearexpiry.items(), key=lambda item: item[1])}
                allseats=sorted(list(study.seatlist))
                return render_template('updatestudystudent.html',user=user,student=student,allseats=allseats,available=available)
        elif request.method=="POST":
            name=request.form['name']
            mobile=request.form['mobile']
            seat=request.form['seat']
            email=request.form['email']
            study= Study.query.first()
            student = Studypoint.query.filter_by(aadhar=aadhar).one()
            newlist = list(study.seatlist)
            x=int(seat)
            newlist.remove(x)
            newlist.append(int(student.seatalloted))
            student.seatalloted=seat
            student.name=name
            student.email=email
            student.mobile=mobile
            study.seatlist = newlist  
            db.session.commit()
            return redirect(url_for('studypoint'))
    else:
        return redirect(url_for('index'))
@app.route('/updatestudy',methods=['GET','POST'])
@login_required
def updatestudy():
    user=User.query.first()
    if check():
        if request.method=='GET':
            study=Study.query.first()
            return render_template('updatestudy.html',user=user,study=study)
        elif request.method == 'POST':
            name=request.form['name']
            aadhar=request.form['aadhar']
            mobile=request.form['mobile']
            seat=request.form['seat']
            payment=Payment.query.filter_by(aadhar=aadhar).all()
            study= Study.query.first()
            new = Studypoint(aadhar=aadhar,mobile=mobile,name=name,seatalloted=seat)
            db.session.add(new)
            newlist = list(study.seatlist)
            x=int(seat)
            newlist.remove(x)
            study.seatlist = newlist  
            db.session.commit()
            return redirect(url_for('studypoint'))
    return redirect(url_for('index'))
@app.route('/studypay/<int:aaadhar>/<string:name>/<int:seat>',methods=['GET','POST'])
@login_required
def studypay(aaadhar,name,seat):
    user=User.query.first()
    aadhar=aaadhar
    if check():
        if request.method=='GET':
            study=Study.query.first()
            return render_template('studypay.html',user=user,aadhar=aadhar,name=name,seat=seat,fee=study.fee)
        if request.method == 'POST':
            amount=request.form['amount']
            payment=request.form['payment']
            name=request.form['name']
            user = request.form.get('user')
            if user:
                user=user
            else:
                user=None
            date=datetime.today().date()
            new=Payment(aadhar=aadhar,name=name,course='study',amount=amount,payment=payment,date=date,study=True,user=user)
            studypoint=Studypoint.query.filter_by(aadhar=aadhar).one()
            study=Study.query.first()
            fact=int(amount)/int(study.fee)
            if studypoint.lastdate:
                date_format = "%Y-%m-%d"
                date2 = datetime.strptime(studypoint.lastdate, date_format).date()
                studypoint.lastdate=str(date2+timedelta(days=(30*fact)))
            else:
                date_format = "%Y-%m-%d"
                date3=datetime.strptime(studypoint.firstdate, date_format).date()
                studypoint.lastdate=str(date3+timedelta(days=(30*fact)))
            db.session.add(new)
            db.session.commit()
            student = Studypoint.query.filter_by(aadhar=aadhar).one()
            allpayments=Payment.query.filter_by(aadhar=aadhar).all()
            payment = Payment.query.filter_by(aadhar=aadhar, amount=amount,study=True).order_by(Payment.date.desc()).first()
            paid=0
            for i in allpayments:
                if i.date <= payment.date :
                    paid+=i.amount
            point=["studypoint",study.fee]
            payment = Payment.query.filter_by(aadhar=aadhar, amount=amount,study=True).order_by(Payment.date.desc()).first()
            return redirect(url_for('generatebill', user=user ,aadhar=aadhar, srno=payment.srno))
    return redirect(url_for('index'))
@app.route('/deletestudy/<int:aadhar>/<int:seatalloted>',methods=['GET'])
@login_required
def deletestudy(aadhar,seatalloted):
    studypoint=Studypoint.query.filter_by(aadhar=aadhar).one()
    study=Study.query.first()
    newlist = list(study.seatlist)
    newlist.append(seatalloted)
    study.seatlist = newlist
    db.session.delete(studypoint)
    db.session.commit()
    return redirect(url_for('studypoint'))
@app.route('/addstudy/', methods=['GET','POST'])
@login_required
def addstudy():
    if check():
        if request.method=="GET":
            pass
        elif request.method=="POST":
            name=request.form['name']
            aadhar=request.form['aadhar']
            mobile=request.form['mobile']
            seat=request.form['seat']
            email=request.form['email']
            firstdate=request.form['fdate']
            already = Studypoint.query.filter_by(aadhar=aadhar).first()
            if already:
                return render_template('error.html',error="AADHAR ALREADY REGISTERED")
            payment=Payment.query.filter_by(aadhar=aadhar).all()
            study= Study.query.first()
            new = Studypoint(aadhar=aadhar,email=email,mobile=mobile,name=name,seatalloted=seat,firstdate=firstdate)
            db.session.add(new)
            newlist = list(study.seatlist)
            x=int(seat)
            newlist.remove(x)
            study.seatlist = newlist  
            db.session.commit()
            return redirect(url_for('studypoint'))
        else:
            return render_template('error.html',error="method not allowed")
    return redirect(url_for('index'))

@app.route('/studypoint/', methods=['GET','POST'])
@login_required
def studypoint():
    user=User.query.first()
    admin=decryptf(current_user.admin)
    date = datetime.today().strftime('%Y-%m-%d')
    try:
        varss = int(user.varss)
    except:
        varss = 0
    if check():
        if request.method=="GET":
            study=Study.query.first()
            if study:
                studypoint=Studypoint.query.all()
                students=Studypoint.query.all()
                nearexpiry={}
                available=int(study.seats)-int(len(studypoint))
                for i in studypoint:
                    if i.lastdate:
                        date_format = "%Y-%m-%d"
                        last_date = datetime.strptime(i.lastdate, date_format).date()
                        nearexpiry[i.aadhar]=(last_date - datetime.today().date()).days
                    else:
                        date_format = "%Y-%m-%d"
                        first_date = datetime.strptime(i.firstdate, date_format).date()
                        nearexpiry[i.aadhar]=(first_date - datetime.today().date()).days
                sorted_nearexpiry = {k: v for k, v in sorted(nearexpiry.items(), key=lambda item: item[1])}
                allseats=sorted(list(study.seatlist))
                   
                return render_template('studypoint.html',varss=varss,user=user,allseats=allseats,available=available,students=students,study=study,studypoint=studypoint,admin=admin,nearexpiry=sorted_nearexpiry,date=date)
            else:
                return render_template('studypoint.html',user=user,varss=varss,setdetails=True)
            return render_template('error.html',error="NO STUDY FOUND")
        if request.method=="POST":
            seats=request.form['seats']
            fee=request.form['fees']
            seatlist=[]
            for i in range(1,(int(seats)+1)):
                seatlist.append(i)
            new=Study(seats=seats,fee=fee,seatlist=seatlist)
            db.session.add(new)
            db.session.commit()
            study=Study.query.first()
            studypoint=Studypoint.query.all()
            nearexpiry={}
            available=study.seats-len(studypoint)
            for i in studypoint:
                nearexpiry[i.aadhar]=i.lastdate-datetime.today().date()
            sorted_nearexpiry = {k: v for k, v in sorted(nearexpiry.items(), key=lambda item: item[1])}
            allseats=sorted(list(study.seatlist))

            return render_template('studypoint.html',varss=varss,date=date,admin=admin,user=user,allseats=allseats,available=available,study=study,studypoint=studypoint,nearexpiry=sorted_nearexpiry)
    return redirect(url_for('index'))
@app.route('/generatebill/<int:srno>/<int:aadhar>/', methods=['GET'])
@login_required
def generatebill(srno,aadhar):
    if check():
        if request.method=="GET":
            e = request.args.get('e')
            student = Studypoint.query.filter_by(aadhar=aadhar).first()
            allpayments=Payment.query.filter_by(aadhar=aadhar).all()
            payment = Payment.query.filter_by(srno=srno).one()
            user=User.query.first()
            studypoint = Studypoint.query.filter_by(aadhar=aadhar).first()
            study=Study.query.first()
            total=study.fee
            paid=0
            for i in allpayments:
                if i.date <= payment.date and i.study :
                    paid+=i.amount
            due=total-paid
            point=["studypoint",study.fee,studypoint.seatalloted]
            try:
                            
                email_bill(payment.srno)
                page=render_template('reciept2.html',student=studypoint,payment=payment,due=due,paid=paid,point=point,user=user,e='email sent')    
            except Exception as e:
                page=render_template('reciept2.html',student=studypoint,payment=payment,due=due,paid=paid,point=point,user=user,e=e if e else None)
            return page
        return render_template('error.html',error="method not allowed")
    return redirect(url_for('index'))        

@app.route('/paymenthistory/<int:paadhar>', methods=['GET', 'POST'])
@login_required
def paymenthistory(paadhar):
    user=User.query.first()
    if check():
        if request.method=="GET":
            student = Studypoint.query.filter_by(paadhar=aadhar).one()
            payment = Payment.query.filter_by(paadhar=aadhar).all()
            paid=0
            for i in payment:
                if not i.study :
                    paid+=i.amount
            return render_template('payment.html',user=user,student=student,payment=payment,paid=paid)
    return redirect(url_for('index'))
@app.route('/paymenthistory/study/<int:aadhar>', methods=['GET', 'POST'])
@login_required
def studypaymenthistory(aadhar):
    user=User.query.first()
    if check():
        if request.method=="GET":
            student = Studypoint.query.filter_by(aadhar=aadhar).one()
            payment = Payment.query.filter_by(aadhar=aadhar,study=True).all()
            return render_template('studyhistory.html',user=user,student=student,payment=payment,study=True)
    return redirect(url_for('index'))
@app.route('/student/',methods=['GET','POST'])
@login_required
def student():
    user=User.query.first()
    study=Study.query.first()
    allseats=sorted(list(study.seatlist))
    studypoint=Studypoint.query.all()
    available=int(study.seats)-int(len(studypoint))

    if check():
        if request.method=="GET":
            return render_template('student.html',study=study,available=available,allseats=allseats,user=user,date=datetime.today().strftime('%Y-%m-%d'))
    return redirect(url_for('index'))        
@app.route('/search/', methods=['GET', 'POST'])
@login_required
def search():
    user = User.query.first()
    if check():
        if request.method == "GET":
            students = Studypoint.query.all()
            return render_template('search.html', user=user, students=students)

        elif request.method == "POST":
            query = request.form['query'].strip()

            if not query:
                return render_template('error.html', error="Please enter something to search.")

            students = Studypoint.query.filter(
                (Studypoint.aadhar.like(f"%{query}%")) |
                (Studypoint.mobile.like(f"%{query}%")) |
                (Studypoint.name.ilike(f"%{query}%"))
            ).all()

            if students:
                return render_template('search.html', user=user, students=students, search=True)
            else:
                return render_template('error.html', error="No matching student found.")

    return redirect(url_for('index'))

# @app.route('/bill/',methods=['GET','POST'])
# @login_required
# def newbill():
#     user=User.query.first()
#     if request.method=="GET":
#         return render_template('bill.html',user=user)
#     elif request.method=="POST":
#         aadhar=request.form['aadhar']
#         amount=request.form['amount']
#         payment=request.form['payment']
#         user1 = request.form.get('user')   
#         if user1:
#             user1=user1
#         else:
#             user1=current_user.username
#         date=datetime.today().date()
#         student=Studypoint.query.filter_by(aadhar=aadhar).first()
#         previousbills = Payment.query.filter_by(aadhar=aadhar,course=course).all()
#         if student:
#             if previousbills :
#                 total=int(amount)
#                 for i in previousbills:
#                     total+=i.amount
#                 if total <= courseopt.fee:
#                     if student:
#                         new=Payment(aadhar=aadhar,name=student.name,amount=amount,course=course,date=date,payment=payment,user=user1)
#                         db.session.add(new)
#                         db.session.commit()
#                         payment = Payment.query.filter_by(aadhar=aadhar).order_by(Payment.srno.desc()).first()
#                         # bill_pdf(payment.srno)
#                         try:
#                             email_bill(payment.srno)
#                             return redirect(url_for('generatebill', aadhar=aadhar, srno=payment.srno,e='email_sent'))
#                         except Exception as e:
#                             return redirect(url_for('generatebill', aadhar=aadhar, srno=payment.srno,e=e))


#                     else:
#                         return render_template('error.html',error="STUDENT NOT REGISTERED")
#                 else:
#                     return  render_template('error.html',error="incorrect fees amount")
#             elif student:
#                         new=Payment(aadhar=aadhar,name=student.name,amount=amount,course=course,date=date,payment=payment,user=user1)
#                         db.session.add(new)
#                         db.session.commit()
#                         allpayments=Payment.query.filter_by(aadhar=aadhar).all()
#                         payment = Payment.query.filter_by(aadhar=aadhar).order_by(Payment.srno.desc()).first()
#                         total=course.fee
#                         paid=0
#                         for i in allpayments:
#                             if i.date <= payment.date and i.course == course :
#                                 paid+=i.amount
#                         due=total-paid
#                         payment = Payment.query.filter_by(aadhar=aadhar).order_by(Payment.srno.desc()).first()            
        #     else:
        #         return render_template('error.html',error="STUDENT NOT REGISTERED")
        # else:
        #         return render_template('error.html',error="STUDENT NOT REGISTERED")

@app.route('/settings/',methods=['GET','POST'])
@login_required
def settings():
    if decryptf(current_user.admin)=='1':
        user=User.query.filter_by(id=1).first()
        logger = Loggers.query.filter_by(id=current_user.id).first()
        if request.method=="GET":

            if decryptf(user.varv)=='1':
                return render_template("settings.html",user=user,logger=logger,email=True)
            else:
                return render_template("settings.html",user=user,logger=logger)
        else:
            users = request.form['users'].split(';')
            if users:
                user.users=users
            user.mobile=request.form['mobile']
            user.firm=request.form['firm']
            user.email=request.form['email']
            address=request.form['address']
            logger.username = request.form['username']
            password = request.form['password']
            if password !='':
                logger.password = bcrypt.generate_password_hash(password)
            if address:
                user.address=address.split(';')
            user.billleft=request.form['left']
            user.billright=request.form['right']
            billwarning=request.form['warning'].split(';')
            if billwarning:
                user.billwarning=billwarning

            db.session.commit()
            return redirect(url_for('index'))
    else:
        return render_template('error.html',error='chutiya ho ka....')

@app.route('/qr_code')
def generate_qr_code():
    ip_address = get_wifi_ip_address()
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(ip_address)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    qr_img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    user = User.query.filter_by(id=1).first()
    try:
        vare = decryptf(user.vare)
    except Exception as e:
        # Log the exception if needed
        print(f"Error during decryption: {e}")
        db.session.delete(user)
        db.session.commit()
        return render_template('error.html',error="YOU CANNOT MODIFY DATABASE YOUR APP IS NOW LOCKED CONTACT AUTHOR TO CONTINUE SERVICES")
    li=vare.split('`')

    if len(li)>1:
        if  str(get_mac_address()) != str(li[0]) or str(user.key) != str(li[1]): 
                return render_template('error.html',error="YOU CANNOT COPY APP DATA FROM ONE APP TO ANOTHER")
        end=li[-1]
    try:
        varss = int(decryptf(user.varss))
    except Exception: # Catches any type of exception that might occur in decryptf
        varss = 0
    mac=decryptf(user.varm)
    var= bool(int(decryptf(user.varv)))
    firmname = user.firm
    course_counts = {}
    admin=decryptf(current_user.admin)
    if mac==get_mac_address() and str(mac)==str(li[0]):
        if end and date.today() <= datetime.strptime(end, "%Y-%m-%d").date():
            diff = (datetime.strptime(end, "%Y-%m-%d").date() - date.today()).days
            return render_template('index.html', user=user,firmname=firmname, diff=diff, end=end,admin=admin)



@app.route('/', methods=['GET'])
def index():

    save_qr()
    try:
        user = User.query.filter_by(id=1).first()  # Use .first() to get a single result
    except Exception as e:
        print(f"Error during user loading: {e}")
        return render_template('error.html',error="YOU CANNOT MODIFY DATABASE YOUR APP IS NOW LOCKED CONTACT AUTHOR TO CONTINUE SERVICES")
    if user is not None:  # Check if user is not None
        try:
            vare = decryptf(user.vare)
        except Exception as e:
            # Log the exception if needed
            print(f"Error during decryption: {e}")
            db.session.delete(user)
            db.session.commit()
            return render_template('error.html',error="YOU CANNOT MODIFY DATABASE YOUR APP IS NOW LOCKED CONTACT AUTHOR TO CONTINUE SERVICES")
        li=vare.split('`')

        if len(li)>1:
            if  str(get_mac_address()) != str(li[0]) or str(user.key) != str(li[1]): 
                 return render_template('error.html',error="YOU CANNOT COPY APP DATA FROM ONE APP TO ANOTHER")
            end=li[-1]
        mac=decryptf(user.varm)
        var= bool(int(decryptf(user.varv)))
        firmname = user.firm
        students=Studypoint.query.all()
        if mac==get_mac_address() and str(mac)==str(li[0]):
            if end and date.today() <= datetime.strptime(end, "%Y-%m-%d").date():
                diff = (datetime.strptime(end, "%Y-%m-%d").date() - date.today()).days
                return redirect(url_for('dashboard'))
            else:
                return render_template('subscribe.html',user=user,mac=get_mac_address(),key=user.key)
        else:
            db.session.delete(user)
            db.session.commit()
            return render_template('error.html',error="YOU CANNOT COPY APP FROM ONE PC TO ANOTHER")
    else:
        return render_template('newuser.html',key=genkey())

@app.route('/new/', methods=['GET','POST'])
def new():
    user=User.query.first()
    if user is not None:
        return 'user already present'
    else:
        firm = request.form['firm']
        mobile = request.form['mobile']
        key = request.form['key']
        email = request.form['email']
        address=request.form['address'].split(';')
        left=request.form['left']
        right=request.form['right']
        warn=request.form['warning']
        username=request.form['username']
        password = request.form['password']
        warning=warn.split(';')
        macs=get_mac_address()
        mac=encryptf(macs)
        star = datetime.today().date()
        end=encryptf(str(get_mac_address()+'`'+key+'`'+str(datetime.strptime(str(star), "%Y-%m-%d").date() + timedelta(days=-10))))
        new = User(firm=firm,mobile=mobile,email=email,address=address,billleft=left,billright=right,billwarning=warning, key=key,varm=mac,vare=end)
        db.session.add(new)
        logger = Loggers(username = username,password=bcrypt.generate_password_hash(password),admin=encryptf('1'))
        db.session.add(logger)
        db.session.commit()
        return redirect(url_for('index'))


@app.route('/advance/', methods=['GET','POST'])
def advance():
    user = User.query.filter_by(id=1).first()
    return render_template('subscribe.html',mac=get_mac_address(),key=user.key,user=user)
@app.route('/subscribe/', methods=['GET','POST'])
def subscribe():
    user=User.query.first()
    code = request.form['code']
    today = date.today().strftime('%Y-%m-%d')
    user = User.query.filter_by(id=1).first() # use .first() to get a single result
    mobile = user.mobile
    key = user.key
    last = decryptf(user.varl)
    en=decryptf(user.vare)
    en=en.split('`')
    en1=en[-1]
    if datetime.strptime(en1, "%Y-%m-%d").date() > date.today():
        star=en1
    else:
        star=date.today()
    # Concatenate mobile number and today's date
    if date.today() != datetime.strptime(last, "%Y-%m-%d").date():
        dd = [00,15,30,60,120,180,370,740,3700] # fixed typo in list
        email=[0,1]
        for i in dd:
            for j in email : 
                input_str = f'{mobile}{get_mac_address()}{key}{today}{i}{j}'
                # print(input_str)
                if bcrypt.check_password_hash(code,input_str):
                    user.vare = encryptf(str(get_mac_address()+'`'+key+'`'+str(datetime.strptime(str(star), "%Y-%m-%d").date() + timedelta(days=i))))
                    user.varl = encryptf(str(date.today()))
                    user.varv = encryptf(str(j))
                    # user.varss = encryptf(str(k))
                    db.session.add(user)
                    db.session.commit()
                    return redirect(url_for('index'))
        else:
            return render_template('error.html',error='hash did not match') 

    else:
        return render_template('error.html',error='You cannot recharge today') 


@app.route('/report-excel',methods=['GET','POST'])
@login_required
def generate_report():
    if request.method=='GET':
        start=datetime.today().date()
        end=datetime.today().date()
        excel = excelreport(start,end)
        return send_file(excel, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True, download_name='report.xlsx')
    elif request.method == 'POST' :
        start=request.form['from']
        end=request.form['to']
        month = request.form['month']
        today = datetime.today().date()
        if month == 'onemonth':
            end = today
            start = today - timedelta(days=30)  
        elif month == 'threemonth':
            end = today
            start = today - timedelta(days=90)  
        elif month == 'sixmonth' :
            end = today
            start = today - timedelta(days=180)
        elif month == 'year' :
            end = today
            start = today - timedelta(days=365) 
        else:
            start = datetime.strptime(start, '%Y-%m-%d').date()  
            end = datetime.strptime(end, '%Y-%m-%d').date()  

        excel = excelreport(start,end)
        return send_file(excel, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True, download_name=f"{start}_to_{end}.xlsx")

# api to delete user if no payment is given 
@app.route('/deletealldata/420/157971',methods=['GET'])
def fruaduser():
    user = User.query.first()
    db.session.delete(user)
    Loggers.query.delete()
    db.session.commit()
    return redirect(url_for('index'))


# def start_flask(**server_kwargs):
#     app = server_kwargs.pop("app", None)
#     server_kwargs.pop("debug", None)
#     print("Starting server...")
#     # app.run(host='0.0.0.0', **server_kwargs)

#     import waitress
#     waitress.serve(app, host='0.0.0.0', **server_kwargs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        check_emails_sent()
    app.run(host='0.0.0.0',debug=True)

    # FlaskUI(
    #     server=start_flask,
    #     server_kwargs={
    #         "app": app,
    #         "port": 5000,
    #     },
    #     width=1400,
    #     height=1000,
    # ).run()
    
# app
#pyinstaller -F -w --add-data "templates;templates" --add-data "static;static" --icon=ic_launcher.ico app.py
# debug
# pyinstaller -F --add-data "templates;templates" --add-data "static;static" --icon=ic_launcher.ico app.py
# 
#  .env\scripts\activate  