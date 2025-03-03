import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_otp_signin(to_email, otp):
    sender_email = "khadeershaik1302@gmail.com"
    sender_password = "cjogelqnyuzdepuy"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP to signin into Application"

    body = f"Your OTP is {otp}. This OTP is valid for 10 minutes."
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, to_email, msg.as_string())
    server.quit()

def send_otp_reset(to_email, otp):
    sender_email = "khadeershaik1302@gmail.com"
    sender_password = "cjogelqnyuzdepuy"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP to reset the password"

    body = f"Your OTP is {otp}. This OTP is valid for 10 minutes."
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, to_email, msg.as_string())
    server.quit()

def send_otp_signup(to_email, otp):
    sender_email = "khadeershaik1302@gmail.com"
    sender_password = "cjogelqnyuzdepuy"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP for creating the new user in application"

    body = f"Your OTP is {otp}. This OTP is valid for 10 minutes."
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, to_email, msg.as_string())
    server.quit()
